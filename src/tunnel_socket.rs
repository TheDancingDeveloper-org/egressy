//! Sockets the gateway itself opens toward tunnel-side services (the in-tunnel
//! DNS resolver, the NAT-PMP gateway).
//!
//! Each is bound to the tunnel interface with `SO_BINDTODEVICE`. The host
//! routes that steer these addresses into the tunnel are deleted with the
//! interface, so an unbound socket would fall back to the management default
//! route and send the query out of the uplink. Bound, the socket can only use
//! the tunnel: when the interface is absent, binding fails with `ENODEV` and the
//! exchange fails closed.

use std::net::SocketAddr;

use tokio::net::{TcpSocket, TcpStream, UdpSocket};

/// A UDP socket connected to `peer`, bound to `interface` when one is given.
pub(crate) async fn udp(peer: SocketAddr, interface: Option<&str>) -> std::io::Result<UdpSocket> {
    let local: SocketAddr = match peer {
        SocketAddr::V4(_) => (std::net::Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(local).await?;
    if let Some(interface) = interface {
        socket.bind_device(Some(interface.as_bytes()))?;
    }
    socket.connect(peer).await?;
    Ok(socket)
}

/// A TCP stream to `peer`, bound to `interface` when one is given.
pub(crate) async fn tcp(peer: SocketAddr, interface: Option<&str>) -> std::io::Result<TcpStream> {
    let socket = match peer {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    if let Some(interface) = interface {
        socket.bind_device(Some(interface.as_bytes()))?;
    }
    socket.connect(peer).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const MISSING: &str = "egressy-nodev0";

    #[tokio::test]
    async fn an_unbound_udp_socket_reaches_a_local_peer() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket = udp(peer.local_addr().unwrap(), None).await.unwrap();
        socket.send(b"x").await.unwrap();
        let mut buf = [0_u8; 1];
        peer.recv(&mut buf).await.unwrap();
    }

    #[tokio::test]
    async fn udp_to_a_missing_tunnel_fails_closed() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let error = udp(peer.local_addr().unwrap(), Some(MISSING))
            .await
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(19), "{error}");
    }

    #[tokio::test]
    async fn tcp_to_a_missing_tunnel_fails_closed() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let error = tcp(listener.local_addr().unwrap(), Some(MISSING))
            .await
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(19), "{error}");
    }
}
