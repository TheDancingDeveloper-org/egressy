use std::{net::Ipv4Addr, time::Duration};

use thiserror::Error;
use tokio::{net::UdpSocket, time::timeout};

const NAT_PMP_PORT: u16 = 5351;

#[derive(Debug, Error)]
pub enum Error {
    #[error("NAT-PMP request timed out")]
    Timeout,
    #[error("NAT-PMP I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid NAT-PMP response: {0}")]
    Invalid(String),
    #[error("NAT-PMP gateway returned result code {0}")]
    Gateway(u16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    Udp,
    Tcp,
}

impl Protocol {
    fn opcode(self) -> u8 {
        match self {
            Self::Udp => 1,
            Self::Tcp => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mapping {
    pub internal_port: u16,
    pub external_port: u16,
    pub lifetime_seconds: u32,
}

#[derive(Clone, Debug)]
pub struct Client {
    gateway: Ipv4Addr,
    initial_timeout: Duration,
}

impl Client {
    pub fn new(gateway: Ipv4Addr) -> Self {
        Self {
            gateway,
            initial_timeout: Duration::from_millis(250),
        }
    }

    pub async fn external_address(&self) -> Result<Ipv4Addr, Error> {
        let response = self.rpc(&[0, 0], 12).await?;
        Ok(Ipv4Addr::new(
            response[8],
            response[9],
            response[10],
            response[11],
        ))
    }

    pub async fn map(
        &self,
        protocol: Protocol,
        internal_port: u16,
        requested_external_port: u16,
        lifetime_seconds: u32,
    ) -> Result<Mapping, Error> {
        let request = encode_mapping_request(
            protocol,
            internal_port,
            requested_external_port,
            lifetime_seconds,
        );
        let response = self.rpc(&request, 16).await?;
        decode_mapping_response(&response)
    }

    async fn rpc(&self, request: &[u8], expected_size: usize) -> Result<Vec<u8>, Error> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
        socket.connect((self.gateway, NAT_PMP_PORT)).await?;
        let mut response = [0_u8; 16];
        let mut wait = self.initial_timeout;
        let bytes = loop {
            socket.send(request).await?;
            match timeout(wait, socket.recv(&mut response)).await {
                Ok(result) => break result?,
                Err(_) if wait < Duration::from_secs(2) => wait *= 2,
                Err(_) => return Err(Error::Timeout),
            }
        };
        if bytes != expected_size {
            return Err(Error::Invalid(format!(
                "expected {expected_size} bytes, received {bytes}"
            )));
        }
        if response[0] != 0 || response[1] != (request[1] | 128) {
            return Err(Error::Invalid("version or opcode mismatch".to_owned()));
        }
        let result = u16::from_be_bytes([response[2], response[3]]);
        if result != 0 {
            return Err(Error::Gateway(result));
        }
        Ok(response[..bytes].to_vec())
    }
}

fn encode_mapping_request(
    protocol: Protocol,
    internal_port: u16,
    requested_external_port: u16,
    lifetime_seconds: u32,
) -> [u8; 12] {
    let mut request = [0_u8; 12];
    request[1] = protocol.opcode();
    request[4..6].copy_from_slice(&internal_port.to_be_bytes());
    request[6..8].copy_from_slice(&requested_external_port.to_be_bytes());
    request[8..12].copy_from_slice(&lifetime_seconds.to_be_bytes());
    request
}

fn decode_mapping_response(response: &[u8]) -> Result<Mapping, Error> {
    if response.len() != 16 {
        return Err(Error::Invalid(format!(
            "mapping response must be 16 bytes, received {}",
            response.len()
        )));
    }
    Ok(Mapping {
        internal_port: u16::from_be_bytes([response[8], response[9]]),
        external_port: u16::from_be_bytes([response[10], response[11]]),
        lifetime_seconds: u32::from_be_bytes([
            response[12],
            response[13],
            response[14],
            response[15],
        ]),
    })
}

pub async fn request_symmetric_mapping(
    client: &Client,
    internal_port: u16,
    requested_external_port: u16,
    lifetime_seconds: u32,
) -> Result<Mapping, Error> {
    let udp = client
        .map(
            Protocol::Udp,
            internal_port,
            requested_external_port,
            lifetime_seconds,
        )
        .await?;
    let tcp = client
        .map(
            Protocol::Tcp,
            internal_port,
            udp.external_port,
            lifetime_seconds,
        )
        .await?;
    if udp.internal_port != tcp.internal_port || udp.external_port != tcp.external_port {
        return Err(Error::Invalid(format!(
            "TCP and UDP mappings differ: UDP {}->{}, TCP {}->{}",
            udp.internal_port, udp.external_port, tcp.internal_port, tcp.external_port
        )));
    }
    Ok(Mapping {
        lifetime_seconds: udp.lifetime_seconds.min(tcp.lifetime_seconds),
        ..udp
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_opcodes_match_rfc_6886() {
        assert_eq!(Protocol::Udp.opcode(), 1);
        assert_eq!(Protocol::Tcp.opcode(), 2);
    }

    #[test]
    fn mapping_request_uses_network_byte_order() {
        let request = encode_mapping_request(Protocol::Tcp, 6881, 45678, 60);
        assert_eq!(request, [0, 2, 0, 0, 0x1a, 0xe1, 0xb2, 0x6e, 0, 0, 0, 60]);
    }

    #[test]
    fn mapping_response_decodes_network_byte_order() {
        let response = [
            0, 130, 0, 0, 0, 0, 0, 1, 0x1a, 0xe1, 0xb2, 0x6e, 0, 0, 0, 60,
        ];
        assert_eq!(
            decode_mapping_response(&response).unwrap(),
            Mapping {
                internal_port: 6881,
                external_port: 45678,
                lifetime_seconds: 60,
            }
        );
    }
}
