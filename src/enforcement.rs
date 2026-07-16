use std::{collections::BTreeMap, net::Ipv4Addr, process::Stdio, sync::Arc};

use anyhow::{bail, Context};
use serde::Deserialize;
use tokio::{io::AsyncWriteExt, process::Command, sync::Mutex};

use crate::{
    config::Config,
    host::{self, ClientCounterRule},
    state::ClientState,
};

pub type Dnat = (u16, Ipv4Addr, u16);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnatTarget {
    pub container_id: String,
    pub address: Ipv4Addr,
    pub port: u16,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClientCounterTotals {
    pub download_packets: u64,
    pub downloaded_bytes: u64,
    pub upload_packets: u64,
    pub uploaded_bytes: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct CounterAccumulator {
    total: u64,
    last_raw: u64,
}

impl CounterAccumulator {
    fn observe(&mut self, raw: u64) {
        let delta = if raw >= self.last_raw {
            raw - self.last_raw
        } else {
            // The kernel object was reset or replaced outside the coordinator.
            raw
        };
        self.total = self.total.saturating_add(delta);
        self.last_raw = raw;
    }

    fn seeded(&mut self) {
        self.last_raw = self.total;
    }
}

#[derive(Clone, Debug)]
struct ClientCounters {
    address: Ipv4Addr,
    download_packets: CounterAccumulator,
    downloaded_bytes: CounterAccumulator,
    upload_packets: CounterAccumulator,
    uploaded_bytes: CounterAccumulator,
}

impl ClientCounters {
    fn new(address: Ipv4Addr) -> Self {
        Self {
            address,
            download_packets: CounterAccumulator::default(),
            downloaded_bytes: CounterAccumulator::default(),
            upload_packets: CounterAccumulator::default(),
            uploaded_bytes: CounterAccumulator::default(),
        }
    }

    fn totals(&self) -> ClientCounterTotals {
        ClientCounterTotals {
            download_packets: self.download_packets.total,
            downloaded_bytes: self.downloaded_bytes.total,
            upload_packets: self.upload_packets.total,
            uploaded_bytes: self.uploaded_bytes.total,
        }
    }

    fn seeded(&mut self) {
        self.download_packets.seeded();
        self.downloaded_bytes.seeded();
        self.upload_packets.seeded();
        self.uploaded_bytes.seeded();
    }
}

#[derive(Default)]
struct DesiredPolicy {
    dnat_allowed: bool,
    dnat_target: Option<DnatTarget>,
    desired_dnat: Option<Dnat>,
    applied_dnat: Option<Dnat>,
    clients: BTreeMap<String, ClientCounters>,
}

#[derive(Clone)]
pub struct EnforcementCoordinator {
    config: Config,
    policy: Arc<Mutex<DesiredPolicy>>,
}

impl EnforcementCoordinator {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            policy: Arc::new(Mutex::new(DesiredPolicy::default())),
        }
    }

    pub async fn reconcile_base(&self) -> anyhow::Result<()> {
        let mut policy = self.policy.lock().await;
        self.apply_locked(&mut policy).await
    }

    pub async fn enable_dnat(&self) {
        self.policy.lock().await.dnat_allowed = true;
    }

    pub async fn disable_dnat(&self) -> anyhow::Result<()> {
        let mut policy = self.policy.lock().await;
        policy.dnat_allowed = false;
        policy.desired_dnat = None;
        self.apply_locked(&mut policy).await
    }

    pub async fn set_dnat_for_target(
        &self,
        dnat: Dnat,
        target: &DnatTarget,
    ) -> anyhow::Result<bool> {
        let mut policy = self.policy.lock().await;
        if !policy.dnat_allowed || policy.dnat_target.as_ref() != Some(target) {
            return Ok(false);
        }
        policy.desired_dnat = Some(dnat);
        self.apply_locked(&mut policy).await?;
        Ok(true)
    }

    pub async fn clear_dnat(&self) -> anyhow::Result<()> {
        let mut policy = self.policy.lock().await;
        policy.desired_dnat = None;
        self.apply_locked(&mut policy).await
    }

    pub async fn dnat_is_applied(&self, dnat: Dnat) -> bool {
        self.policy.lock().await.applied_dnat == Some(dnat)
    }

    pub async fn reconcile_clients(
        &self,
        clients: &BTreeMap<String, ClientState>,
        invalidate_dnat: bool,
    ) -> anyhow::Result<()> {
        let mut policy = self.policy.lock().await;
        self.observe_kernel_locked(&mut policy).await?;
        let dnat_target = select_dnat_target(clients);
        if invalidate_dnat || policy.dnat_target != dnat_target {
            policy.desired_dnat = None;
        }
        policy.dnat_target = dnat_target;
        sync_clients(&mut policy, clients);
        self.apply_locked(&mut policy).await
    }

    pub async fn sample_client_counters(
        &self,
    ) -> anyhow::Result<BTreeMap<String, ClientCounterTotals>> {
        let mut policy = self.policy.lock().await;
        self.observe_kernel_locked(&mut policy).await?;
        Ok(policy
            .clients
            .iter()
            .map(|(container_id, counters)| (container_id.clone(), counters.totals()))
            .collect())
    }

    async fn apply_locked(&self, policy: &mut DesiredPolicy) -> anyhow::Result<()> {
        if !self.config.reconcile.apply_gateway_firewall {
            return Ok(());
        }
        self.observe_kernel_locked(policy).await?;
        let counter_rules = policy
            .clients
            .iter()
            .map(|(container_id, counters)| {
                let totals = counters.totals();
                ClientCounterRule {
                    container_id: container_id.clone(),
                    address: counters.address,
                    download_packets: totals.download_packets,
                    downloaded_bytes: totals.downloaded_bytes,
                    upload_packets: totals.upload_packets,
                    uploaded_bytes: totals.uploaded_bytes,
                }
            })
            .collect::<Vec<_>>();
        let rules =
            host::render_gateway_firewall(&self.config, policy.desired_dnat, &counter_rules);
        let exists = table_exists().await?;
        let transaction = if exists {
            format!("delete table inet egressy\n{rules}")
        } else {
            rules
        };
        let mut child = Command::new("nft")
            .args(["-f", "-"])
            .kill_on_drop(true)
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        child
            .stdin
            .take()
            .context("opening nft stdin")?
            .write_all(transaction.as_bytes())
            .await?;
        let output = child.wait_with_output().await?;
        if !output.status.success() {
            bail!(
                "nft reconciliation failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        for counters in policy.clients.values_mut() {
            counters.seeded();
        }
        policy.applied_dnat = policy.desired_dnat;
        Ok(())
    }

    async fn observe_kernel_locked(&self, policy: &mut DesiredPolicy) -> anyhow::Result<()> {
        if !self.config.reconcile.apply_gateway_firewall || !table_exists().await? {
            return Ok(());
        }
        let output = Command::new("nft")
            .args(["-j", "list", "counters", "table", "inet", "egressy"])
            .output()
            .await?;
        if !output.status.success() {
            bail!(
                "nft counter read failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        let document: NftDocument =
            serde_json::from_slice(&output.stdout).context("decoding nft counter response")?;
        for item in document.nftables {
            let Some(counter) = item.counter else {
                continue;
            };
            for (container_id, client) in &mut policy.clients {
                if counter.name == host::client_counter_name("down", container_id) {
                    client.download_packets.observe(counter.packets);
                    client.downloaded_bytes.observe(counter.bytes);
                } else if counter.name == host::client_counter_name("up", container_id) {
                    client.upload_packets.observe(counter.packets);
                    client.uploaded_bytes.observe(counter.bytes);
                }
            }
        }
        Ok(())
    }
}

fn select_dnat_target(clients: &BTreeMap<String, ClientState>) -> Option<DnatTarget> {
    let mut targets = clients
        .values()
        .filter(|client| client.port_forward_target && client.compliant)
        .filter_map(|client| {
            Some(DnatTarget {
                container_id: client.container_id.clone(),
                address: client.ipv4_address,
                port: client.target_port?,
            })
        });
    let target = targets.next()?;
    targets.next().is_none().then_some(target)
}

fn sync_clients(policy: &mut DesiredPolicy, clients: &BTreeMap<String, ClientState>) {
    policy.clients.retain(|container_id, counters| {
        clients
            .get(container_id)
            .is_some_and(|client| client.ipv4_address == counters.address)
    });
    for (container_id, client) in clients {
        if !client.ipv4_address.is_unspecified()
            && !container_id.is_empty()
            && container_id
                .chars()
                .all(|character| character.is_ascii_alphanumeric())
        {
            policy
                .clients
                .entry(container_id.clone())
                .or_insert_with(|| ClientCounters::new(client.ipv4_address));
        }
    }
}

async fn table_exists() -> anyhow::Result<bool> {
    Ok(Command::new("nft")
        .args(["list", "table", "inet", "egressy"])
        .output()
        .await?
        .status
        .success())
}

#[derive(Deserialize)]
struct NftDocument {
    nftables: Vec<NftItem>,
}

#[derive(Deserialize)]
struct NftItem {
    counter: Option<NftCounter>,
}

#[derive(Deserialize)]
struct NftCounter {
    name: String,
    packets: u64,
    bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(id: &str, address: &str) -> ClientState {
        ClientState {
            container_id: id.to_owned(),
            usage_id: format!("test:{id}"),
            usage_id_source: crate::state::UsageIdentitySource::ExplicitLabel,
            name: id.to_owned(),
            ipv4_address: address.parse().unwrap(),
            port_forward_target: false,
            target_port: None,
            compliant: true,
            compliance_message: "test".to_owned(),
            running: true,
            ipv6_address: None,
            networks: vec!["vpn-egress".to_owned()],
            port_forward_label_valid: true,
            route_intent: crate::state::RouteIntentState::default(),
            traffic: crate::state::ClientTrafficState::default(),
        }
    }

    #[test]
    fn counter_accumulator_is_monotonic_across_kernel_reset() {
        let mut counter = CounterAccumulator::default();
        counter.observe(100);
        counter.observe(125);
        counter.observe(5);
        assert_eq!(counter.total, 130);
    }

    #[test]
    fn seeding_prevents_recounting_preserved_totals() {
        let mut counter = CounterAccumulator::default();
        counter.observe(100);
        counter.seeded();
        counter.observe(112);
        assert_eq!(counter.total, 112);
    }

    #[test]
    fn removed_clients_drop_their_counter_objects() {
        let mut policy = DesiredPolicy::default();
        let clients = [("old".to_owned(), client("old", "172.30.0.10"))].into();
        sync_clients(&mut policy, &clients);
        assert!(policy.clients.contains_key("old"));

        sync_clients(&mut policy, &BTreeMap::new());
        assert!(policy.clients.is_empty());
    }

    #[test]
    fn address_reuse_does_not_transfer_previous_client_totals() {
        let mut policy = DesiredPolicy::default();
        let old_clients = [("old".to_owned(), client("old", "172.30.0.10"))].into();
        sync_clients(&mut policy, &old_clients);
        policy.clients.get_mut("old").unwrap().uploaded_bytes.total = 1_000;

        let new_clients = [("new".to_owned(), client("new", "172.30.0.10"))].into();
        sync_clients(&mut policy, &new_clients);
        assert!(!policy.clients.contains_key("old"));
        assert_eq!(policy.clients["new"].uploaded_bytes.total, 0);
    }

    #[test]
    fn same_client_address_change_starts_new_totals() {
        let mut policy = DesiredPolicy::default();
        let old = [("same".to_owned(), client("same", "172.30.0.10"))].into();
        sync_clients(&mut policy, &old);
        policy
            .clients
            .get_mut("same")
            .unwrap()
            .downloaded_bytes
            .total = 1_000;

        let moved = [("same".to_owned(), client("same", "172.30.0.11"))].into();
        sync_clients(&mut policy, &moved);
        assert_eq!(
            policy.clients["same"].address,
            "172.30.0.11".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(policy.clients["same"].downloaded_bytes.total, 0);
    }

    #[test]
    fn desired_and_applied_dnat_are_distinct_until_successful_apply() {
        let mut policy = DesiredPolicy::default();
        let mapping = (45678, "172.30.0.10".parse().unwrap(), 6881);
        policy.desired_dnat = Some(mapping);
        assert_eq!(policy.applied_dnat, None);
        policy.applied_dnat = policy.desired_dnat;
        assert_eq!(policy.applied_dnat, Some(mapping));
    }

    #[test]
    fn disabled_dnat_owner_rejects_an_inflight_renewal() {
        let mut policy = DesiredPolicy::default();
        let mapping = (45678, "172.30.0.10".parse().unwrap(), 6881);
        assert!(!policy.dnat_allowed);
        policy.desired_dnat = policy.dnat_allowed.then_some(mapping);
        assert_eq!(policy.desired_dnat, None);
    }

    #[test]
    fn target_identity_distinguishes_address_reuse() {
        let mut old_client = client("old", "172.30.0.10");
        old_client.port_forward_target = true;
        old_client.target_port = Some(6881);
        let mut replacement_client = client("new", "172.30.0.10");
        replacement_client.port_forward_target = true;
        replacement_client.target_port = Some(6881);
        let old = [("old".into(), old_client)].into();
        let replacement = [("new".into(), replacement_client)].into();
        assert_ne!(select_dnat_target(&old), select_dnat_target(&replacement));
    }
}
