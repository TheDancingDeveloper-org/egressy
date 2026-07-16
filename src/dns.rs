use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{bail, Context};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};
use tracing::{debug, warn};

use crate::{
    control::StatePublisher,
    domain::{CheckStatus, Impact},
};

const MAX_DNS_MESSAGE: usize = 65_535;

#[derive(Clone)]
pub struct Settings {
    pub listen: SocketAddr,
    pub upstream: SocketAddr,
    pub timeout: Duration,
    pub max_concurrent_queries: usize,
    pub publisher: Option<StatePublisher>,
}

pub async fn run(settings: Settings) -> anyhow::Result<()> {
    let udp = Arc::new(
        UdpSocket::bind(settings.listen)
            .await
            .context("binding UDP DNS listener")?,
    );
    let tcp = TcpListener::bind(settings.listen)
        .await
        .context("binding TCP DNS listener")?;
    let permits = Arc::new(Semaphore::new(settings.max_concurrent_queries));

    tokio::try_join!(
        serve_udp(Arc::clone(&udp), settings.clone(), Arc::clone(&permits)),
        serve_tcp(tcp, settings, permits)
    )?;
    Ok(())
}

pub async fn supervise(settings: Settings) -> anyhow::Result<()> {
    let mut attempt = 0_u32;
    loop {
        match run(settings.clone()).await {
            Ok(()) => return Ok(()),
            Err(error) => {
                attempt = attempt.saturating_add(1);
                let delay = crate::recovery::retry_delay_seconds(attempt, 300);
                if let Some(publisher) = &settings.publisher {
                    publisher
                        .observe(
                            "dns.listener",
                            CheckStatus::Failed,
                            Impact::Critical,
                            "dns.listener_failed",
                            "The DNS listener stopped and will be restarted",
                            Some(crate::runtime::unix_ms() + delay * 1000),
                            Some(attempt),
                        )
                        .await;
                }
                warn!(%error, attempt, delay, "DNS supervisor restarting listeners");
                tokio::time::sleep(Duration::from_secs(delay)).await;
            }
        }
    }
}

async fn serve_udp(
    listener: Arc<UdpSocket>,
    settings: Settings,
    permits: Arc<Semaphore>,
) -> anyhow::Result<()> {
    let mut workers = JoinSet::new();
    loop {
        let mut query = vec![0_u8; MAX_DNS_MESSAGE];
        let (length, client) = tokio::select! {
            received = listener.recv_from(&mut query) => received?,
            completed = workers.join_next(), if !workers.is_empty() => {
                if let Some(Err(error)) = completed {
                    warn!(%error, "UDP DNS worker panicked");
                }
                continue;
            }
        };
        query.truncate(length);
        let listener = Arc::clone(&listener);
        let settings = settings.clone();
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            warn!(%client, "DNS concurrency limit reached");
            continue;
        };
        workers.spawn(async move {
            let _permit = permit;
            match forward_query(&query, settings.upstream, settings.timeout).await {
                Ok((response, tcp_used)) => {
                    observe_success(settings.publisher.as_ref(), tcp_used).await;
                    if let Err(error) = listener.send_to(&response, client).await {
                        warn!(%client, %error, "sending DNS response failed");
                    }
                }
                Err(error) => {
                    observe_failure(settings.publisher.as_ref(), &error).await;
                    warn!(%client, %error, "DNS forwarding failed")
                }
            }
        });
    }
}

async fn serve_tcp(
    listener: TcpListener,
    settings: Settings,
    permits: Arc<Semaphore>,
) -> anyhow::Result<()> {
    let mut workers = JoinSet::new();
    loop {
        let (mut client, address) = tokio::select! {
            accepted = listener.accept() => accepted?,
            completed = workers.join_next(), if !workers.is_empty() => {
                if let Some(Err(error)) = completed {
                    warn!(%error, "TCP DNS worker panicked");
                }
                continue;
            }
        };
        let settings = settings.clone();
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            warn!(%address, "DNS concurrency limit reached");
            continue;
        };
        workers.spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_tcp_client(&mut client, &settings).await {
                warn!(%address, %error, "TCP DNS forwarding failed");
            }
        });
    }
}

async fn handle_tcp_client(client: &mut TcpStream, settings: &Settings) -> anyhow::Result<()> {
    let query = read_tcp_message(client, settings.timeout).await?;
    let response = tcp_exchange(&query, settings.upstream, settings.timeout).await?;
    observe_success(settings.publisher.as_ref(), true).await;
    write_tcp_message(client, &response, settings.timeout).await?;
    Ok(())
}

async fn forward_query(
    query: &[u8],
    upstream: SocketAddr,
    request_timeout: Duration,
) -> anyhow::Result<(Vec<u8>, bool)> {
    validate_dns_message(query)?;
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(upstream).await?;
    timeout(request_timeout, socket.send(query))
        .await
        .context("DNS upstream UDP send timed out")??;
    let mut response = vec![0_u8; MAX_DNS_MESSAGE];
    let length = timeout(request_timeout, socket.recv(&mut response))
        .await
        .context("DNS upstream UDP response timed out")??;
    response.truncate(length);
    validate_response(query, &response)?;
    if is_truncated(&response)? {
        debug!("DNS UDP response truncated; retrying over TCP");
        return Ok((tcp_exchange(query, upstream, request_timeout).await?, true));
    }
    Ok((response, false))
}

async fn observe_success(publisher: Option<&StatePublisher>, tcp_used: bool) {
    let Some(publisher) = publisher else { return };
    publisher
        .observe(
            "dns.upstream_udp",
            CheckStatus::Healthy,
            Impact::Critical,
            "dns.udp_healthy",
            "The in-tunnel resolver answered over UDP",
            None,
            None,
        )
        .await;
    if tcp_used {
        publisher
            .observe(
                "dns.upstream_tcp",
                CheckStatus::Healthy,
                Impact::Critical,
                "dns.tcp_healthy",
                "The in-tunnel resolver answered over TCP",
                None,
                None,
            )
            .await;
    }
}

async fn observe_failure(publisher: Option<&StatePublisher>, error: &anyhow::Error) {
    let Some(publisher) = publisher else { return };
    let code = if error.to_string().contains("timed out") {
        "dns.upstream_timeout"
    } else {
        "dns.upstream_invalid"
    };
    publisher
        .observe(
            "dns.upstream_udp",
            CheckStatus::Degraded,
            Impact::Critical,
            code,
            "The in-tunnel resolver did not return a valid response",
            None,
            None,
        )
        .await;
}

async fn tcp_exchange(
    query: &[u8],
    upstream: SocketAddr,
    request_timeout: Duration,
) -> anyhow::Result<Vec<u8>> {
    validate_dns_message(query)?;
    let mut stream = timeout(request_timeout, TcpStream::connect(upstream))
        .await
        .context("DNS upstream TCP connect timed out")??;
    write_tcp_message(&mut stream, query, request_timeout).await?;
    let response = read_tcp_message(&mut stream, request_timeout).await?;
    validate_response(query, &response)?;
    Ok(response)
}

async fn read_tcp_message(stream: &mut TcpStream, wait: Duration) -> anyhow::Result<Vec<u8>> {
    let length = timeout(wait, stream.read_u16())
        .await
        .context("DNS TCP length timed out")?? as usize;
    if !(12..=MAX_DNS_MESSAGE).contains(&length) {
        bail!("invalid DNS TCP message length");
    }
    let mut message = vec![0; length];
    timeout(wait, stream.read_exact(&mut message))
        .await
        .context("DNS TCP body timed out")??;
    Ok(message)
}

async fn write_tcp_message(
    stream: &mut TcpStream,
    message: &[u8],
    wait: Duration,
) -> anyhow::Result<()> {
    validate_dns_message(message)?;
    let length =
        u16::try_from(message.len()).map_err(|_| io::Error::other("DNS message too large"))?;
    timeout(wait, stream.write_u16(length))
        .await
        .context("DNS TCP length write timed out")??;
    timeout(wait, stream.write_all(message))
        .await
        .context("DNS TCP body write timed out")??;
    Ok(())
}

fn validate_dns_message(message: &[u8]) -> anyhow::Result<()> {
    if message.len() < 12 || message.len() > MAX_DNS_MESSAGE {
        bail!("malformed DNS message length");
    }
    Ok(())
}

fn validate_response(query: &[u8], response: &[u8]) -> anyhow::Result<()> {
    validate_dns_message(response)?;
    if response[..2] != query[..2] {
        bail!("DNS response transaction ID mismatch");
    }
    if response[2] & 0x80 == 0 {
        bail!("DNS response bit is not set");
    }
    Ok(())
}

fn is_truncated(message: &[u8]) -> anyhow::Result<bool> {
    validate_dns_message(message)?;
    Ok(message[2] & 0x02 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(flags: u16) -> Vec<u8> {
        let mut message = vec![0; 12];
        message[0..2].copy_from_slice(&42_u16.to_be_bytes());
        message[2..4].copy_from_slice(&flags.to_be_bytes());
        message
    }

    #[test]
    fn detects_udp_truncation_flag() {
        assert!(is_truncated(&packet(0x8200)).unwrap());
        assert!(!is_truncated(&packet(0x8000)).unwrap());
    }

    #[test]
    fn validates_transaction_and_response_bits() {
        let query = packet(0x0100);
        validate_response(&query, &packet(0x8100)).unwrap();
        assert!(validate_response(&query, &packet(0x0100)).is_err());
        let mut mismatched = packet(0x8100);
        mismatched[1] = 1;
        assert!(validate_response(&query, &mismatched).is_err());
    }
}
