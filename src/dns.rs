use std::{
    io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{bail, Context};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{watch, Mutex, Semaphore},
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
    pub upstream: watch::Receiver<Option<SocketAddr>>,
    pub timeout: Duration,
    pub max_concurrent_queries: usize,
    pub udp_attempts: u32,
    pub failure_threshold: u32,
    pub success_threshold: u32,
    pub publisher: Option<StatePublisher>,
}

static UDP_QUERIES: AtomicU64 = AtomicU64::new(0);
static UDP_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static UDP_TIMEOUTS: AtomicU64 = AtomicU64::new(0);
static UDP_EXHAUSTED: AtomicU64 = AtomicU64::new(0);
static TCP_FALLBACKS: AtomicU64 = AtomicU64::new(0);
static TCP_FALLBACK_SUCCESSES: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DebouncedStatus {
    Unknown,
    Healthy,
    Degraded,
}

#[derive(Debug)]
struct DnsHealthState {
    status: DebouncedStatus,
    consecutive_failures: u32,
    consecutive_successes: u32,
    failure_threshold: u32,
    success_threshold: u32,
}

impl DnsHealthState {
    fn new(failure_threshold: u32, success_threshold: u32) -> Self {
        Self {
            status: DebouncedStatus::Unknown,
            consecutive_failures: 0,
            consecutive_successes: 0,
            failure_threshold,
            success_threshold,
        }
    }

    fn record(&mut self, success: bool) -> Option<DebouncedStatus> {
        if success {
            self.consecutive_failures = 0;
            self.consecutive_successes = self.consecutive_successes.saturating_add(1);
            match self.status {
                DebouncedStatus::Unknown => {
                    self.status = DebouncedStatus::Healthy;
                    Some(self.status)
                }
                DebouncedStatus::Healthy => Some(self.status),
                DebouncedStatus::Degraded
                    if self.consecutive_successes >= self.success_threshold =>
                {
                    self.status = DebouncedStatus::Healthy;
                    Some(self.status)
                }
                DebouncedStatus::Degraded => None,
            }
        } else {
            self.consecutive_successes = 0;
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
            match self.status {
                DebouncedStatus::Unknown | DebouncedStatus::Healthy
                    if self.consecutive_failures >= self.failure_threshold =>
                {
                    self.status = DebouncedStatus::Degraded;
                    Some(self.status)
                }
                DebouncedStatus::Degraded => Some(self.status),
                DebouncedStatus::Unknown | DebouncedStatus::Healthy => None,
            }
        }
    }
}

struct ForwardResult {
    response: Vec<u8>,
    tcp_used: bool,
    udp_succeeded: bool,
    failed_udp_attempts: u32,
}

pub fn prometheus_metrics() -> String {
    format!(
        "# HELP egressy_dns_udp_queries_total Client UDP DNS queries received.\n\
# TYPE egressy_dns_udp_queries_total counter\n\
egressy_dns_udp_queries_total {}\n\
# HELP egressy_dns_upstream_udp_attempts_total Upstream UDP DNS attempts.\n\
# TYPE egressy_dns_upstream_udp_attempts_total counter\n\
egressy_dns_upstream_udp_attempts_total {}\n\
# HELP egressy_dns_upstream_udp_timeouts_total Upstream UDP DNS attempt timeouts.\n\
# TYPE egressy_dns_upstream_udp_timeouts_total counter\n\
egressy_dns_upstream_udp_timeouts_total {}\n\
# HELP egressy_dns_upstream_udp_exhausted_total Queries that exhausted all upstream UDP attempts.\n\
# TYPE egressy_dns_upstream_udp_exhausted_total counter\n\
egressy_dns_upstream_udp_exhausted_total {}\n\
# HELP egressy_dns_upstream_tcp_fallbacks_total TCP fallbacks after UDP truncation or failure.\n\
# TYPE egressy_dns_upstream_tcp_fallbacks_total counter\n\
egressy_dns_upstream_tcp_fallbacks_total {}\n\
# HELP egressy_dns_upstream_tcp_fallback_successes_total Successful TCP fallbacks.\n\
# TYPE egressy_dns_upstream_tcp_fallback_successes_total counter\n\
egressy_dns_upstream_tcp_fallback_successes_total {}\n",
        UDP_QUERIES.load(Ordering::Relaxed),
        UDP_ATTEMPTS.load(Ordering::Relaxed),
        UDP_TIMEOUTS.load(Ordering::Relaxed),
        UDP_EXHAUSTED.load(Ordering::Relaxed),
        TCP_FALLBACKS.load(Ordering::Relaxed),
        TCP_FALLBACK_SUCCESSES.load(Ordering::Relaxed),
    )
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
    let health = Arc::new(Mutex::new(DnsHealthState::new(
        settings.failure_threshold,
        settings.success_threshold,
    )));

    tokio::try_join!(
        serve_udp(
            Arc::clone(&udp),
            settings.clone(),
            Arc::clone(&permits),
            health
        ),
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
    health: Arc<Mutex<DnsHealthState>>,
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
        UDP_QUERIES.fetch_add(1, Ordering::Relaxed);
        let listener = Arc::clone(&listener);
        let settings = settings.clone();
        let health = Arc::clone(&health);
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            warn!(%client, "DNS concurrency limit reached");
            continue;
        };
        workers.spawn(async move {
            let _permit = permit;
            let Some(upstream) = *settings.upstream.borrow() else {
                observe_udp_health(settings.publisher.as_ref(), &health, false).await;
                warn!(%client, "DNS upstream is not configured");
                return;
            };
            match forward_query(&query, upstream, settings.timeout, settings.udp_attempts).await {
                Ok(result) => {
                    observe_udp_health(
                        settings.publisher.as_ref(),
                        &health,
                        result.udp_succeeded,
                    )
                    .await;
                    if result.tcp_used {
                        observe_tcp_success(settings.publisher.as_ref()).await;
                        if !result.udp_succeeded {
                            warn!(%client, attempts = settings.udp_attempts, "DNS UDP attempts failed; response recovered over in-tunnel TCP");
                        }
                    }
                    if result.failed_udp_attempts > 0 && result.udp_succeeded {
                        warn!(
                            %client,
                            failed_udp_attempts = result.failed_udp_attempts,
                            "DNS UDP query recovered after an in-tunnel upstream retry"
                        );
                    }
                    if let Err(error) = listener.send_to(&result.response, client).await {
                        warn!(%client, %error, "sending DNS response failed");
                    }
                }
                Err(error) => {
                    observe_udp_health(settings.publisher.as_ref(), &health, false).await;
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
    let upstream = (*settings.upstream.borrow()).context("DNS upstream is not configured")?;
    let response = tcp_exchange(&query, upstream, settings.timeout).await?;
    observe_tcp_success(settings.publisher.as_ref()).await;
    write_tcp_message(client, &response, settings.timeout).await?;
    Ok(())
}

async fn forward_query(
    query: &[u8],
    upstream: SocketAddr,
    request_timeout: Duration,
    udp_attempts: u32,
) -> anyhow::Result<ForwardResult> {
    validate_dns_message(query)?;
    let mut last_error = None;
    let mut failed_udp_attempts = 0;
    for attempt in 1..=udp_attempts {
        UDP_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
        match udp_exchange(query, upstream, request_timeout).await {
            Ok(response) if is_truncated(&response)? => {
                debug!("DNS UDP response truncated; retrying over TCP");
                TCP_FALLBACKS.fetch_add(1, Ordering::Relaxed);
                let response = tcp_exchange(query, upstream, request_timeout).await?;
                TCP_FALLBACK_SUCCESSES.fetch_add(1, Ordering::Relaxed);
                return Ok(ForwardResult {
                    response,
                    tcp_used: true,
                    udp_succeeded: true,
                    failed_udp_attempts,
                });
            }
            Ok(response) => {
                return Ok(ForwardResult {
                    response,
                    tcp_used: false,
                    udp_succeeded: true,
                    failed_udp_attempts,
                });
            }
            Err(error) => {
                failed_udp_attempts += 1;
                if error.to_string().contains("timed out") {
                    UDP_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
                }
                debug!(%error, attempt, udp_attempts, "DNS upstream UDP attempt failed");
                last_error = Some(error);
            }
        }
    }
    UDP_EXHAUSTED.fetch_add(1, Ordering::Relaxed);
    TCP_FALLBACKS.fetch_add(1, Ordering::Relaxed);
    match tcp_exchange(query, upstream, request_timeout).await {
        Ok(response) => {
            TCP_FALLBACK_SUCCESSES.fetch_add(1, Ordering::Relaxed);
            Ok(ForwardResult {
                response,
                tcp_used: true,
                udp_succeeded: false,
                failed_udp_attempts,
            })
        }
        Err(tcp_error) => Err(tcp_error.context(format!(
            "DNS upstream UDP attempts exhausted: {}",
            last_error
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "unknown UDP failure".to_owned())
        ))),
    }
}

async fn udp_exchange(
    query: &[u8],
    upstream: SocketAddr,
    request_timeout: Duration,
) -> anyhow::Result<Vec<u8>> {
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
    Ok(response)
}

async fn observe_udp_health(
    publisher: Option<&StatePublisher>,
    health: &Mutex<DnsHealthState>,
    success: bool,
) {
    let Some(publisher) = publisher else { return };
    let observation = health.lock().await.record(success);
    let Some(status) = observation else { return };
    let healthy = status == DebouncedStatus::Healthy;
    publisher
        .observe(
            "dns.upstream_udp",
            if healthy {
                CheckStatus::Healthy
            } else {
                CheckStatus::Degraded
            },
            Impact::Critical,
            if healthy {
                "dns.udp_healthy"
            } else {
                "dns.upstream_udp_failures"
            },
            if healthy {
                "The in-tunnel resolver answered over UDP"
            } else {
                "Consecutive queries exhausted all in-tunnel UDP attempts"
            },
            None,
            None,
        )
        .await;
}

async fn observe_tcp_success(publisher: Option<&StatePublisher>) {
    let Some(publisher) = publisher else { return };
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

    #[test]
    fn dns_health_requires_consecutive_failures_and_recovery_successes() {
        let mut health = DnsHealthState::new(3, 2);
        assert_eq!(health.record(true), Some(DebouncedStatus::Healthy));
        assert_eq!(health.record(false), None);
        assert_eq!(health.record(true), Some(DebouncedStatus::Healthy));
        assert_eq!(health.record(false), None);
        assert_eq!(health.record(false), None);
        assert_eq!(health.record(false), Some(DebouncedStatus::Degraded));
        assert_eq!(health.record(true), None);
        assert_eq!(health.record(false), Some(DebouncedStatus::Degraded));
        assert_eq!(health.record(true), None);
        assert_eq!(health.record(true), Some(DebouncedStatus::Healthy));
    }
}
