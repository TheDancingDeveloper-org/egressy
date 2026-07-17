use std::{
    fmt,
    net::{IpAddr, SocketAddr},
};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAX_PROFILE_BYTES: usize = 256 * 1024;
const MAX_PEERS: usize = 32;
const MAX_LIST_VALUES: usize = 128;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret(String);

impl Secret {
    fn parse(value: &str, field: &'static str, line: usize) -> Result<Self, ProfileError> {
        let value = value.trim();
        if value.is_empty() || value.len() > 128 {
            return Err(ProfileError::at(
                field,
                line,
                "secret must be 1-128 characters",
            ));
        }
        Ok(Self(value.to_owned()))
    }

    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret([REDACTED])")
    }
}

#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct WireGuardProfile {
    pub interface: Interface,
    pub peers: Vec<Peer>,
}

#[derive(Clone, Debug, Default, Zeroize, ZeroizeOnDrop)]
pub struct Interface {
    pub private_key: Option<Secret>,
    #[zeroize(skip)]
    pub addresses: Vec<IpNet>,
    #[zeroize(skip)]
    pub dns: Vec<IpAddr>,
    pub listen_port: Option<u16>,
    pub mtu: Option<u16>,
}

#[derive(Clone, Debug, Default, Zeroize, ZeroizeOnDrop)]
pub struct Peer {
    pub public_key: String,
    pub preshared_key: Option<Secret>,
    pub endpoint: Option<Endpoint>,
    #[zeroize(skip)]
    pub allowed_ips: Vec<IpNet>,
    pub persistent_keepalive: Option<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Zeroize)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub address_family: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyKind {
    NoChange,
    DnsReload,
    SyncConf,
    SyncConfAndRoutes,
    TunnelRecycle,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RedactedProfile {
    pub interface: RedactedInterface,
    pub peers: Vec<RedactedPeer>,
    pub peer_count: usize,
    pub ipv4_full_tunnel: bool,
    pub full_tunnel_peer: Option<usize>,
    pub warnings: Vec<ProfileWarning>,
    pub apply_kind: ApplyKind,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RedactedInterface {
    pub private_key_configured: bool,
    pub addresses: Vec<String>,
    pub dns: Vec<String>,
    pub listen_port: Option<u16>,
    pub mtu: Option<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RedactedPeer {
    pub public_key: String,
    pub preshared_key_configured: bool,
    pub endpoint: Option<Endpoint>,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive: Option<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProfileWarning {
    pub code: String,
    pub field: String,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredProfileInput {
    #[serde(default)]
    pub private_key: Option<String>,
    pub addresses: Vec<String>,
    pub dns: Vec<String>,
    pub listen_port: Option<u16>,
    pub mtu: Option<u16>,
    pub peers: Vec<StructuredPeerInput>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredPeerInput {
    pub public_key: String,
    #[serde(default)]
    pub preshared_key: Option<String>,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive: Option<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProfileError {
    pub code: String,
    pub field: Option<String>,
    pub line: Option<usize>,
    pub message: String,
}

impl ProfileError {
    fn at(field: impl Into<String>, line: usize, message: impl Into<String>) -> Self {
        Self {
            code: "invalid_wireguard_profile".to_owned(),
            field: Some(field.into()),
            line: Some(line),
            message: message.into(),
        }
    }

    fn general(message: impl Into<String>) -> Self {
        Self {
            code: "invalid_wireguard_profile".to_owned(),
            field: None,
            line: None,
            message: message.into(),
        }
    }
}

impl fmt::Display for ProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.field, self.line) {
            (Some(field), Some(line)) => {
                write!(formatter, "line {line}, {field}: {}", self.message)
            }
            _ => formatter.write_str(&self.message),
        }
    }
}

impl std::error::Error for ProfileError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Section {
    Interface,
    Peer(usize),
}

impl WireGuardProfile {
    pub fn parse(source: &[u8]) -> Result<Self, ProfileError> {
        if source.len() > MAX_PROFILE_BYTES {
            return Err(ProfileError::general("profile exceeds the 256 KiB limit"));
        }
        let source = std::str::from_utf8(source)
            .map_err(|_| ProfileError::general("profile must be valid UTF-8"))?;
        let mut profile = Self {
            interface: Interface::default(),
            peers: Vec::new(),
        };
        let mut section = None;
        let mut interface_seen = false;

        for (offset, raw) in source.lines().enumerate() {
            let line_number = offset + 1;
            let line = raw.split_once('#').map_or(raw, |(value, _)| value).trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('[') {
                section = match line.to_ascii_lowercase().as_str() {
                    "[interface]" if !interface_seen && profile.peers.is_empty() => {
                        interface_seen = true;
                        Some(Section::Interface)
                    }
                    "[interface]" => {
                        return Err(ProfileError::at(
                            "section",
                            line_number,
                            "exactly one [Interface] section must appear before peers",
                        ));
                    }
                    "[peer]" if interface_seen => {
                        if profile.peers.len() == MAX_PEERS {
                            return Err(ProfileError::at(
                                "section",
                                line_number,
                                "profile exceeds the 32-peer limit",
                            ));
                        }
                        profile.peers.push(Peer::default());
                        Some(Section::Peer(profile.peers.len() - 1))
                    }
                    "[peer]" => {
                        return Err(ProfileError::at(
                            "section",
                            line_number,
                            "[Interface] must appear before [Peer]",
                        ));
                    }
                    _ => {
                        return Err(ProfileError::at(
                            "section",
                            line_number,
                            "unknown or malformed section",
                        ));
                    }
                };
                continue;
            }
            let current = section.ok_or_else(|| {
                ProfileError::at(
                    "section",
                    line_number,
                    "directive appears outside a section",
                )
            })?;
            let (key, value) = line.split_once('=').ok_or_else(|| {
                ProfileError::at("directive", line_number, "directive must contain '='")
            })?;
            let key = key.trim();
            let value = value.trim();
            reject_owned_or_dangerous(key, line_number)?;
            match current {
                Section::Interface => profile.parse_interface(key, value, line_number)?,
                Section::Peer(index) => profile.parse_peer(index, key, value, line_number)?,
            }
        }

        if !interface_seen {
            return Err(ProfileError::general("profile has no [Interface] section"));
        }
        if profile.peers.is_empty() {
            return Err(ProfileError::general("profile has no [Peer] section"));
        }
        if profile.interface.private_key.is_none() {
            return Err(ProfileError::general("Interface.PrivateKey is required"));
        }
        for (index, peer) in profile.peers.iter().enumerate() {
            if peer.public_key.is_empty() {
                return Err(ProfileError::general(format!(
                    "Peer {} is missing PublicKey",
                    index + 1
                )));
            }
            if peer.allowed_ips.is_empty() {
                return Err(ProfileError::general(format!(
                    "Peer {} is missing AllowedIPs",
                    index + 1
                )));
            }
        }
        profile.full_tunnel_peer()?;
        Ok(profile)
    }

    fn parse_interface(&mut self, key: &str, value: &str, line: usize) -> Result<(), ProfileError> {
        match key.to_ascii_lowercase().as_str() {
            "privatekey" => set_once(
                &mut self.interface.private_key,
                Secret::parse(value, "Interface.PrivateKey", line)?,
                "Interface.PrivateKey",
                line,
            ),
            "address" => extend_unique(
                &mut self.interface.addresses,
                parse_list(value, "Interface.Address", line)?,
                "Interface.Address",
                line,
            ),
            "dns" => extend_unique(
                &mut self.interface.dns,
                parse_list(value, "Interface.DNS", line)?,
                "Interface.DNS",
                line,
            ),
            "listenport" => set_once(
                &mut self.interface.listen_port,
                parse_number(value, "Interface.ListenPort", line, 1, u16::MAX)?,
                "Interface.ListenPort",
                line,
            ),
            "mtu" => set_once(
                &mut self.interface.mtu,
                parse_number(value, "Interface.MTU", line, 576, u16::MAX)?,
                "Interface.MTU",
                line,
            ),
            _ => Err(ProfileError::at(
                format!("Interface.{key}"),
                line,
                "unknown directive",
            )),
        }
    }

    fn parse_peer(
        &mut self,
        index: usize,
        key: &str,
        value: &str,
        line: usize,
    ) -> Result<(), ProfileError> {
        let field = |name: &str| format!("Peer[{}].{name}", index + 1);
        let peer = &mut self.peers[index];
        match key.to_ascii_lowercase().as_str() {
            "publickey" => set_string_once(&mut peer.public_key, value, &field("PublicKey"), line),
            "presharedkey" => {
                let name = field("PresharedKey");
                set_once(
                    &mut peer.preshared_key,
                    Secret::parse(value, "Peer.PresharedKey", line)?,
                    &name,
                    line,
                )
            }
            "endpoint" => {
                let name = field("Endpoint");
                set_once(
                    &mut peer.endpoint,
                    parse_endpoint(value, &name, line)?,
                    &name,
                    line,
                )
            }
            "allowedips" => {
                let name = field("AllowedIPs");
                extend_unique(
                    &mut peer.allowed_ips,
                    parse_list(value, &name, line)?,
                    &name,
                    line,
                )
            }
            "persistentkeepalive" => {
                let name = field("PersistentKeepalive");
                set_once(
                    &mut peer.persistent_keepalive,
                    parse_number(value, &name, line, 0, u16::MAX)?,
                    &name,
                    line,
                )
            }
            _ => Err(ProfileError::at(field(key), line, "unknown directive")),
        }
    }

    pub fn full_tunnel_peer(&self) -> Result<usize, ProfileError> {
        let peers = self
            .peers
            .iter()
            .enumerate()
            .filter(|(_, peer)| peer.allowed_ips.iter().any(is_ipv4_default))
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        match peers.as_slice() {
            [index] => Ok(*index),
            [] => Err(ProfileError::general(
                "exactly one peer must route 0.0.0.0/0; none do",
            )),
            _ => Err(ProfileError::general(
                "exactly one peer must route 0.0.0.0/0; routing is ambiguous",
            )),
        }
    }

    pub fn redacted(&self, active: Option<&Self>) -> RedactedProfile {
        let full_tunnel_peer = self.full_tunnel_peer().ok();
        let mut warnings = Vec::new();
        if self
            .interface
            .addresses
            .iter()
            .any(|address| address.addr().is_ipv6())
        {
            warnings.push(ProfileWarning {
                code: "ipv6_interface_unprotected".to_owned(),
                field: "Interface.Address".to_owned(),
                message: "IPv6 interface addresses are preserved, but Egressy protects enrolled IPv4 traffic only".to_owned(),
            });
        }
        if self.interface.dns.iter().any(IpAddr::is_ipv6) {
            warnings.push(ProfileWarning {
                code: "ipv6_dns_unsupported".to_owned(),
                field: "Interface.DNS".to_owned(),
                message: "IPv6 DNS servers cannot be used by the IPv4-only DNS forwarder"
                    .to_owned(),
            });
        }
        if self
            .peers
            .iter()
            .flat_map(|peer| &peer.allowed_ips)
            .any(|network| network.addr().is_ipv6())
        {
            warnings.push(ProfileWarning {
                code: "ipv6_routes_unprotected".to_owned(),
                field: "Peer.AllowedIPs".to_owned(),
                message: "IPv6 allowed ranges are preserved, but do not imply enrolled-client IPv6 leak protection".to_owned(),
            });
        }
        RedactedProfile {
            interface: RedactedInterface {
                private_key_configured: self.interface.private_key.is_some(),
                addresses: stringify(&self.interface.addresses),
                dns: stringify(&self.interface.dns),
                listen_port: self.interface.listen_port,
                mtu: self.interface.mtu,
            },
            peers: self
                .peers
                .iter()
                .map(|peer| RedactedPeer {
                    public_key: peer.public_key.clone(),
                    preshared_key_configured: peer.preshared_key.is_some(),
                    endpoint: peer.endpoint.clone(),
                    allowed_ips: stringify(&peer.allowed_ips),
                    persistent_keepalive: peer.persistent_keepalive,
                })
                .collect(),
            peer_count: self.peers.len(),
            ipv4_full_tunnel: full_tunnel_peer.is_some(),
            full_tunnel_peer,
            warnings,
            apply_kind: active.map_or(ApplyKind::TunnelRecycle, |old| old.diff(self)),
        }
    }

    pub fn render(&self) -> String {
        let mut output = String::from("[Interface]\n");
        if let Some(secret) = &self.interface.private_key {
            output.push_str("PrivateKey = ");
            output.push_str(secret.expose());
            output.push('\n');
        }
        if !self.interface.addresses.is_empty() {
            output.push_str("Address = ");
            output.push_str(&stringify(&self.interface.addresses).join(", "));
            output.push('\n');
        }
        // wg-quick must not alter resolv.conf. Egressy consumes DNS itself.
        output.push_str("Table = off\n");
        if let Some(port) = self.interface.listen_port {
            output.push_str(&format!("ListenPort = {port}\n"));
        }
        if let Some(mtu) = self.interface.mtu {
            output.push_str(&format!("MTU = {mtu}\n"));
        }
        for peer in &self.peers {
            output.push_str("\n[Peer]\nPublicKey = ");
            output.push_str(&peer.public_key);
            output.push('\n');
            if let Some(secret) = &peer.preshared_key {
                output.push_str("PresharedKey = ");
                output.push_str(secret.expose());
                output.push('\n');
            }
            if let Some(endpoint) = &peer.endpoint {
                let host = if endpoint.address_family == "ipv6" {
                    format!("[{}]", endpoint.host)
                } else {
                    endpoint.host.clone()
                };
                output.push_str(&format!("Endpoint = {host}:{}\n", endpoint.port));
            }
            output.push_str("AllowedIPs = ");
            output.push_str(&stringify(&peer.allowed_ips).join(", "));
            output.push('\n');
            if let Some(value) = peer.persistent_keepalive {
                output.push_str(&format!("PersistentKeepalive = {value}\n"));
            }
        }
        output
    }

    pub fn render_source(&self) -> String {
        let mut output = self.render();
        if !self.interface.dns.is_empty() {
            let insertion = format!("DNS = {}\n", stringify(&self.interface.dns).join(", "));
            let table = output
                .find("Table = off\n")
                .expect("renderer always owns Table");
            output.insert_str(table, &insertion);
        }
        output = output.replacen("Table = off\n", "", 1);
        output
    }

    pub fn edit(&self, input: StructuredProfileInput) -> Result<Self, ProfileError> {
        use std::fmt::Write;
        let mut source = String::from("[Interface]\nPrivateKey = ");
        source.push_str(
            input
                .private_key
                .as_deref()
                .or_else(|| self.interface.private_key.as_ref().map(Secret::expose))
                .ok_or_else(|| ProfileError::general("Interface.PrivateKey is required"))?,
        );
        source.push('\n');
        if !input.addresses.is_empty() {
            writeln!(source, "Address = {}", input.addresses.join(", ")).unwrap();
        }
        if !input.dns.is_empty() {
            writeln!(source, "DNS = {}", input.dns.join(", ")).unwrap();
        }
        if let Some(port) = input.listen_port {
            writeln!(source, "ListenPort = {port}").unwrap();
        }
        if let Some(mtu) = input.mtu {
            writeln!(source, "MTU = {mtu}").unwrap();
        }
        for peer in input.peers {
            source.push_str("\n[Peer]\nPublicKey = ");
            source.push_str(&peer.public_key);
            source.push('\n');
            let preserved_psk = self
                .peers
                .iter()
                .find(|active| active.public_key == peer.public_key)
                .and_then(|active| active.preshared_key.as_ref().map(Secret::expose));
            if let Some(secret) = peer.preshared_key.as_deref().or(preserved_psk) {
                source.push_str("PresharedKey = ");
                source.push_str(secret);
                source.push('\n');
            }
            if let Some(endpoint) = peer.endpoint {
                source.push_str("Endpoint = ");
                source.push_str(&endpoint);
                source.push('\n');
            }
            source.push_str("AllowedIPs = ");
            source.push_str(&peer.allowed_ips.join(", "));
            source.push('\n');
            if let Some(value) = peer.persistent_keepalive {
                writeln!(source, "PersistentKeepalive = {value}").unwrap();
            }
        }
        let result = Self::parse(source.as_bytes());
        source.zeroize();
        result
    }

    pub fn render_syncconf(&self) -> String {
        let mut output = String::from("[Interface]\n");
        if let Some(secret) = &self.interface.private_key {
            output.push_str("PrivateKey = ");
            output.push_str(secret.expose());
            output.push('\n');
        }
        if let Some(port) = self.interface.listen_port {
            output.push_str(&format!("ListenPort = {port}\n"));
        }
        for peer in &self.peers {
            output.push_str("\n[Peer]\nPublicKey = ");
            output.push_str(&peer.public_key);
            output.push('\n');
            if let Some(secret) = &peer.preshared_key {
                output.push_str("PresharedKey = ");
                output.push_str(secret.expose());
                output.push('\n');
            }
            if let Some(endpoint) = &peer.endpoint {
                let host = if endpoint.address_family == "ipv6" {
                    format!("[{}]", endpoint.host)
                } else {
                    endpoint.host.clone()
                };
                output.push_str(&format!("Endpoint = {host}:{}\n", endpoint.port));
            }
            output.push_str("AllowedIPs = ");
            output.push_str(&stringify(&peer.allowed_ips).join(", "));
            output.push('\n');
            if let Some(value) = peer.persistent_keepalive {
                output.push_str(&format!("PersistentKeepalive = {value}\n"));
            }
        }
        output
    }

    pub fn ipv4_dns(&self) -> Vec<std::net::Ipv4Addr> {
        self.interface
            .dns
            .iter()
            .filter_map(|address| match address {
                IpAddr::V4(address) => Some(*address),
                IpAddr::V6(_) => None,
            })
            .collect()
    }

    pub fn diff(&self, candidate: &Self) -> ApplyKind {
        if self.render() == candidate.render() && self.interface.dns == candidate.interface.dns {
            return ApplyKind::NoChange;
        }
        let transport_same = self.interface.private_key.as_ref().map(Secret::expose)
            == candidate.interface.private_key.as_ref().map(Secret::expose)
            && self.interface.addresses == candidate.interface.addresses
            && self.interface.listen_port == candidate.interface.listen_port
            && self.interface.mtu == candidate.interface.mtu
            && peers_equal(&self.peers, &candidate.peers);
        if transport_same {
            return ApplyKind::DnsReload;
        }
        if self.interface.private_key.as_ref().map(Secret::expose)
            != candidate.interface.private_key.as_ref().map(Secret::expose)
            || self.interface.addresses != candidate.interface.addresses
            || self.interface.listen_port != candidate.interface.listen_port
            || self.interface.mtu != candidate.interface.mtu
            || self.peers.len() != candidate.peers.len()
        {
            return ApplyKind::TunnelRecycle;
        }
        if self
            .peers
            .iter()
            .zip(&candidate.peers)
            .any(|(old, new)| old.allowed_ips != new.allowed_ips)
        {
            ApplyKind::SyncConfAndRoutes
        } else {
            ApplyKind::SyncConf
        }
    }
}

fn peers_equal(left: &[Peer], right: &[Peer]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            left.public_key == right.public_key
                && left.preshared_key.as_ref().map(Secret::expose)
                    == right.preshared_key.as_ref().map(Secret::expose)
                && left.endpoint == right.endpoint
                && left.allowed_ips == right.allowed_ips
                && left.persistent_keepalive == right.persistent_keepalive
        })
}

fn reject_owned_or_dangerous(key: &str, line: usize) -> Result<(), ProfileError> {
    let normalized = key.to_ascii_lowercase();
    if normalized == "table" {
        return Err(ProfileError::at(
            "Interface.Table",
            line,
            "Table is owned by Egressy and must not be supplied",
        ));
    }
    if matches!(
        normalized.as_str(),
        "saveconfig" | "preup" | "postup" | "predown" | "postdown"
    ) {
        return Err(ProfileError::at(
            key,
            line,
            "privileged hooks and SaveConfig are prohibited",
        ));
    }
    Ok(())
}

fn set_once<T>(
    target: &mut Option<T>,
    value: T,
    field: &str,
    line: usize,
) -> Result<(), ProfileError> {
    if target.is_some() {
        return Err(ProfileError::at(
            field,
            line,
            "directive may appear only once",
        ));
    }
    *target = Some(value);
    Ok(())
}

fn set_string_once(
    target: &mut String,
    value: &str,
    field: &str,
    line: usize,
) -> Result<(), ProfileError> {
    if !target.is_empty() {
        return Err(ProfileError::at(
            field,
            line,
            "directive may appear only once",
        ));
    }
    if value.is_empty() || value.len() > 128 {
        return Err(ProfileError::at(
            field,
            line,
            "key must be 1-128 characters",
        ));
    }
    *target = value.to_owned();
    Ok(())
}

fn extend_unique<T: Eq>(
    target: &mut Vec<T>,
    values: Vec<T>,
    field: &str,
    line: usize,
) -> Result<(), ProfileError> {
    if target.len() + values.len() > MAX_LIST_VALUES {
        return Err(ProfileError::at(
            field,
            line,
            "field exceeds the 128-value limit",
        ));
    }
    for value in values {
        if target.contains(&value) {
            return Err(ProfileError::at(field, line, "duplicate value"));
        }
        target.push(value);
    }
    Ok(())
}

fn parse_list<T>(value: &str, field: &str, line: usize) -> Result<Vec<T>, ProfileError>
where
    T: std::str::FromStr,
{
    let values = value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .parse()
                .map_err(|_| ProfileError::at(field, line, "invalid address or network"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if values.is_empty() {
        return Err(ProfileError::at(
            field,
            line,
            "at least one value is required",
        ));
    }
    Ok(values)
}

fn parse_number(
    value: &str,
    field: &str,
    line: usize,
    minimum: u16,
    maximum: u16,
) -> Result<u16, ProfileError> {
    let value = value
        .parse::<u16>()
        .map_err(|_| ProfileError::at(field, line, "invalid integer"))?;
    if !(minimum..=maximum).contains(&value) {
        return Err(ProfileError::at(
            field,
            line,
            "integer is outside the supported range",
        ));
    }
    Ok(value)
}

fn parse_endpoint(value: &str, field: &str, line: usize) -> Result<Endpoint, ProfileError> {
    if let Ok(socket) = value.parse::<SocketAddr>() {
        return Ok(Endpoint {
            host: socket.ip().to_string(),
            port: socket.port(),
            address_family: if socket.is_ipv4() { "ipv4" } else { "ipv6" }.to_owned(),
        });
    }
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| ProfileError::at(field, line, "endpoint must contain a port"))?;
    let host = host.trim();
    if host.starts_with('[') || host.ends_with(']') {
        return Err(ProfileError::at(
            field,
            line,
            "malformed bracketed endpoint",
        ));
    }
    if host.is_empty()
        || host.len() > 253
        || !host
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '.'))
    {
        return Err(ProfileError::at(
            field,
            line,
            "endpoint hostname is invalid",
        ));
    }
    Ok(Endpoint {
        host: host.to_ascii_lowercase(),
        port: port
            .parse()
            .map_err(|_| ProfileError::at(field, line, "endpoint port is invalid"))?,
        address_family: "hostname".to_owned(),
    })
}

fn stringify<T: ToString>(values: &[T]) -> Vec<String> {
    values.iter().map(ToString::to_string).collect()
}

fn is_ipv4_default(network: &IpNet) -> bool {
    matches!(network, IpNet::V4(network) if network.prefix_len() == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: &str = "# fake fixture\n[Interface]\nPrivateKey = fake-private\nAddress = 10.2.0.2/32, fd00::2/128\nDNS = 10.2.0.1\n\n[Peer]\nPublicKey = fake-public\nPresharedKey = fake-psk\nEndpoint = vpn.example.test:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n";

    #[test]
    fn parses_redacts_and_normalizes_a_conventional_profile() {
        let profile = WireGuardProfile::parse(PROFILE.as_bytes()).unwrap();
        let redacted = profile.redacted(None);
        assert!(redacted.interface.private_key_configured);
        assert!(redacted.peers[0].preshared_key_configured);
        assert!(redacted.ipv4_full_tunnel);
        assert_eq!(
            redacted.peers[0].endpoint.as_ref().unwrap().host,
            "vpn.example.test"
        );
        let rendered = profile.render();
        assert!(rendered.contains("Table = off"));
        assert!(!rendered.contains("DNS ="));
        assert!(rendered.contains("PrivateKey = fake-private"));
        let json = serde_json::to_string(&redacted).unwrap();
        assert!(!json.contains("fake-private"));
        assert!(!json.contains("fake-psk"));
    }

    #[test]
    fn endpoints_support_raw_ip_hostname_and_bracketed_ipv6() {
        for (endpoint, family) in [
            ("192.0.2.1:51820", "ipv4"),
            ("vpn.example.test:443", "hostname"),
            ("[2001:db8::1]:53", "ipv6"),
        ] {
            let source = PROFILE.replace("vpn.example.test:51820", endpoint);
            let parsed = WireGuardProfile::parse(source.as_bytes()).unwrap();
            assert_eq!(
                parsed.peers[0].endpoint.as_ref().unwrap().address_family,
                family
            );
        }
    }

    #[test]
    fn rejects_dangerous_owned_and_unknown_directives_without_echoing_values() {
        for line in [
            "Table = 123",
            "SaveConfig = true",
            "PostUp = echo very-secret-value",
            "Mystery = very-secret-value",
        ] {
            let source = PROFILE.replace("DNS = 10.2.0.1", line);
            let error = WireGuardProfile::parse(source.as_bytes()).unwrap_err();
            let message = error.to_string();
            assert!(error.line.is_some());
            assert!(!message.contains("very-secret-value"));
        }
    }

    #[test]
    fn requires_one_unambiguous_ipv4_default_peer() {
        let missing = PROFILE.replace("0.0.0.0/0, ", "");
        assert!(WireGuardProfile::parse(missing.as_bytes()).is_err());
        let ambiguous = format!("{PROFILE}\n[Peer]\nPublicKey = second\nAllowedIPs = 0.0.0.0/0\n");
        assert!(WireGuardProfile::parse(ambiguous.as_bytes()).is_err());
    }

    #[test]
    fn classifies_dns_syncconf_routes_and_recycle_changes() {
        let active = WireGuardProfile::parse(PROFILE.as_bytes()).unwrap();
        let dns =
            WireGuardProfile::parse(PROFILE.replace("10.2.0.1", "10.2.0.53").as_bytes()).unwrap();
        assert_eq!(active.diff(&dns), ApplyKind::DnsReload);
        let endpoint =
            WireGuardProfile::parse(PROFILE.replace("51820", "51821").as_bytes()).unwrap();
        assert_eq!(active.diff(&endpoint), ApplyKind::SyncConf);
        let allowed =
            WireGuardProfile::parse(PROFILE.replace("::/0", "10.0.0.0/8").as_bytes()).unwrap();
        assert_eq!(active.diff(&allowed), ApplyKind::SyncConfAndRoutes);
        let mtu = WireGuardProfile::parse(
            PROFILE
                .replace("DNS = 10.2.0.1", "DNS = 10.2.0.1\nMTU = 1380")
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(active.diff(&mtu), ApplyKind::TunnelRecycle);
    }

    #[test]
    fn provider_fixtures_use_the_same_neutral_parser() {
        for (source, peers) in [
            (
                include_bytes!("../tests/fixtures/wireguard/proton.conf").as_slice(),
                1,
            ),
            (
                include_bytes!("../tests/fixtures/wireguard/mullvad.conf").as_slice(),
                1,
            ),
            (
                include_bytes!("../tests/fixtures/wireguard/mullvad-multihop.conf").as_slice(),
                2,
            ),
        ] {
            let profile = WireGuardProfile::parse(source).unwrap();
            assert_eq!(profile.peers.len(), peers);
            assert!(profile.redacted(None).ipv4_full_tunnel);
        }
    }

    #[test]
    fn structured_edit_preserves_omitted_secrets_and_replaces_explicit_secrets() {
        let active = WireGuardProfile::parse(PROFILE.as_bytes()).unwrap();
        let input = StructuredProfileInput {
            private_key: None,
            addresses: vec!["10.9.0.2/32".into()],
            dns: vec!["10.9.0.1".into()],
            listen_port: None,
            mtu: Some(1380),
            peers: vec![StructuredPeerInput {
                public_key: "fake-public".into(),
                preshared_key: None,
                endpoint: Some("new.example.test:51820".into()),
                allowed_ips: vec!["0.0.0.0/0".into()],
                persistent_keepalive: Some(25),
            }],
        };
        let edited = active.edit(input).unwrap().render_source();
        assert!(edited.contains("PrivateKey = fake-private"));
        assert!(edited.contains("PresharedKey = fake-psk"));
        assert!(edited.contains("Address = 10.9.0.2/32"));
        assert!(!edited.contains("Table ="));

        let replacement = StructuredProfileInput {
            private_key: Some("new-private".into()),
            addresses: vec!["10.9.0.2/32".into()],
            dns: vec![],
            listen_port: None,
            mtu: None,
            peers: vec![StructuredPeerInput {
                public_key: "fake-public".into(),
                preshared_key: Some("new-psk".into()),
                endpoint: None,
                allowed_ips: vec!["0.0.0.0/0".into()],
                persistent_keepalive: None,
            }],
        };
        let edited = active.edit(replacement).unwrap().render_source();
        assert!(edited.contains("PrivateKey = new-private"));
        assert!(edited.contains("PresharedKey = new-psk"));
        assert!(!edited.contains("fake-private"));
        assert!(!edited.contains("fake-psk"));
    }
}
