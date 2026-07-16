use std::{collections::BTreeMap, process::Stdio, time::Duration};

use anyhow::{bail, Context};
use clap::Parser;
use egressy::isolation::{render_bridge_policy, CounterValue, IsolationMode, IsolationPolicy};
use serde::Deserialize;
use tokio::{process::Command, signal, time::interval};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(version, about = "Host-side vpn-egress bridge isolation owner")]
struct Cli {
    #[arg(
        long,
        env = "EGRESSY_ISOLATION_POLICY_URL",
        default_value = "http://127.0.0.1:8080/api/v2/isolation-policy"
    )]
    policy_url: String,
    #[arg(long, env = "EGRESSY_ISOLATION_MODE", default_value = "disabled")]
    mode: IsolationMode,
    #[arg(long, env = "EGRESSY_ISOLATION_INTERVAL_SECONDS", default_value_t = 5)]
    interval_seconds: u64,
    #[arg(long, env = "EGRESSY_ISOLATION_STALE_SECONDS", default_value_t = 30)]
    stale_seconds: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "egressy=info".into()),
        )
        .init();
    let cli = Cli::parse();
    validate(&cli)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()?;
    let mut ticker = interval(Duration::from_secs(cli.interval_seconds));
    let mut last_policy_fingerprint = None;
    let mut last_reported_counters = BTreeMap::new();
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("isolation agent shutdown requested; the last reviewed policy remains installed");
                return Ok(());
            }
            _ = ticker.tick() => {
                if cli.mode == IsolationMode::Disabled {
                    apply_policy(IsolationMode::Disabled, "").await?;
                    last_policy_fingerprint = Some("Disabled:".to_owned());
                    continue;
                }
                match fetch_policy(&client, &cli).await {
                    Ok(policy) => {
                        let counters = read_counters().await.unwrap_or_default();
                        report_violation_changes(
                            &violation_changes(&policy, &counters, &last_reported_counters),
                        );
                        last_reported_counters = counters.clone();
                        let (effective_mode, rules) = render_bridge_policy(&policy, cli.mode, &counters);
                        let fingerprint = policy_fingerprint(&policy, effective_mode);
                        if last_policy_fingerprint.as_deref() != Some(&fingerprint) {
                            apply_policy(effective_mode, &rules).await?;
                            last_policy_fingerprint = Some(fingerprint);
                            info!(requested_mode = ?cli.mode, ?effective_mode, participants = policy.participants.len(), "bridge isolation policy applied");
                        }
                    }
                    Err(error) => {
                        warn!(%error, "isolation policy unavailable; retaining the last applied host policy");
                    }
                }
            }
        }
    }
}

fn validate(cli: &Cli) -> anyhow::Result<()> {
    let url = reqwest::Url::parse(&cli.policy_url).context("invalid isolation policy URL")?;
    if url.scheme() != "http" || !matches!(url.host_str(), Some("127.0.0.1" | "localhost")) {
        bail!("isolation policy URL must use host-loopback HTTP");
    }
    if cli.interval_seconds == 0 || cli.stale_seconds < cli.interval_seconds {
        bail!("isolation interval must be non-zero and shorter than its stale threshold");
    }
    Ok(())
}

async fn fetch_policy(client: &reqwest::Client, cli: &Cli) -> anyhow::Result<IsolationPolicy> {
    let response = client
        .get(&cli.policy_url)
        .send()
        .await?
        .error_for_status()?;
    const MAX_POLICY_BYTES: u64 = 1_048_576;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_POLICY_BYTES)
    {
        bail!("isolation policy response is too large");
    }
    let body = response.bytes().await?;
    if body.len() as u64 > MAX_POLICY_BYTES {
        bail!("isolation policy response is too large");
    }
    let policy: IsolationPolicy = serde_json::from_slice(&body)?;
    if policy.schema_version != 1 {
        bail!("unsupported isolation policy schema");
    }
    policy
        .subnet
        .parse::<ipnet::Ipv4Net>()
        .context("invalid isolation policy subnet")?;
    if policy_is_stale(&policy, cli.stale_seconds, crate_unix_ms()) {
        bail!("isolation policy snapshot is stale");
    }
    Ok(policy)
}

fn policy_is_stale(policy: &IsolationPolicy, stale_seconds: u64, now_unix_ms: u64) -> bool {
    let tolerance = stale_seconds.saturating_mul(1_000);
    now_unix_ms.saturating_sub(policy.generated_at_unix_ms) > tolerance
        || policy.generated_at_unix_ms.saturating_sub(now_unix_ms) > tolerance
}

fn policy_fingerprint(policy: &IsolationPolicy, effective_mode: IsolationMode) -> String {
    let mut stable_policy = policy.clone();
    stable_policy.generated_at_unix_ms = 0;
    format!(
        "{effective_mode:?}:{}",
        serde_json::to_string(&stable_policy).expect("isolation policy is serializable")
    )
}

#[derive(Debug, Eq, PartialEq)]
struct ViolationChange {
    source_id: String,
    destination_id: String,
    packets: u64,
    bytes: u64,
}

fn violation_changes(
    policy: &IsolationPolicy,
    current: &BTreeMap<String, CounterValue>,
    previous: &BTreeMap<String, CounterValue>,
) -> Vec<ViolationChange> {
    let mut changes = Vec::new();
    for source in &policy.participants {
        for destination in &policy.participants {
            if source.ipv4_address == destination.ipv4_address {
                continue;
            }
            let name = egressy::isolation::pair_counter_name(
                &source.container_id,
                &destination.container_id,
            );
            let value = current.get(&name).copied().unwrap_or_default();
            let old = previous.get(&name).copied().unwrap_or_default();
            if value.packets > old.packets || value.bytes > old.bytes {
                changes.push(ViolationChange {
                    source_id: source
                        .isolation_id
                        .clone()
                        .unwrap_or_else(|| source.name.clone()),
                    destination_id: destination
                        .isolation_id
                        .clone()
                        .unwrap_or_else(|| destination.name.clone()),
                    packets: value.packets,
                    bytes: value.bytes,
                });
            }
        }
    }
    let value = current
        .get("isolation_unresolved")
        .copied()
        .unwrap_or_default();
    let old = previous
        .get("isolation_unresolved")
        .copied()
        .unwrap_or_default();
    if value.packets > old.packets || value.bytes > old.bytes {
        changes.push(ViolationChange {
            source_id: "unresolved".to_owned(),
            destination_id: "unresolved".to_owned(),
            packets: value.packets,
            bytes: value.bytes,
        });
    }
    changes
}

fn report_violation_changes(changes: &[ViolationChange]) {
    for change in changes {
        warn!(
            source = %change.source_id,
            destination = %change.destination_id,
            packets = change.packets,
            bytes = change.bytes,
            "bridge isolation observed unauthorized lateral traffic"
        );
    }
}

async fn apply_policy(mode: IsolationMode, rules: &str) -> anyhow::Result<()> {
    let exists = table_exists().await?;
    if mode == IsolationMode::Disabled {
        if exists {
            run_nft("delete table bridge egressy_isolation\n").await?;
        }
        return Ok(());
    }
    let script = if exists {
        format!("delete table bridge egressy_isolation\n{rules}")
    } else {
        rules.to_owned()
    };
    run_nft(&script).await
}

async fn table_exists() -> anyhow::Result<bool> {
    Ok(Command::new("nft")
        .args(["list", "table", "bridge", "egressy_isolation"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await?
        .success())
}

async fn run_nft(script: &str) -> anyhow::Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    use tokio::io::AsyncWriteExt;
    child
        .stdin
        .take()
        .context("nft stdin unavailable")?
        .write_all(script.as_bytes())
        .await?;
    let output = child.wait_with_output().await?;
    if !output.status.success() {
        bail!("nft isolation transaction failed");
    }
    Ok(())
}

async fn read_counters() -> anyhow::Result<BTreeMap<String, CounterValue>> {
    let output = Command::new("nft")
        .args(["-j", "list", "table", "bridge", "egressy_isolation"])
        .output()
        .await?;
    if !output.status.success() {
        return Ok(BTreeMap::new());
    }
    let document: NftDocument = serde_json::from_slice(&output.stdout)?;
    Ok(document
        .nftables
        .into_iter()
        .filter_map(|item| item.counter)
        .map(|counter| {
            (
                counter.name,
                CounterValue {
                    packets: counter.packets,
                    bytes: counter.bytes,
                },
            )
        })
        .collect())
}

fn crate_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
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
    use egressy::isolation::{build_policy, IsolationCandidate};

    fn policy(now: u64) -> IsolationPolicy {
        build_policy(
            "vpn-egress",
            "br-vpn-egress",
            "172.30.0.0/24".parse().unwrap(),
            vec![
                IsolationCandidate {
                    container_id: "one-container".into(),
                    name: "one".into(),
                    ipv4_address: "172.30.0.10".parse().unwrap(),
                    isolation_id: Some("one".into()),
                    allow: None,
                },
                IsolationCandidate {
                    container_id: "two-container".into(),
                    name: "two".into(),
                    ipv4_address: "172.30.0.11".parse().unwrap(),
                    isolation_id: Some("two".into()),
                    allow: None,
                },
            ],
            now,
        )
    }

    #[test]
    fn rejects_non_loopback_policy_url() {
        assert!(validate(&Cli {
            policy_url: "http://egressy:8080/api/v2/isolation-policy".into(),
            mode: IsolationMode::Audit,
            interval_seconds: 5,
            stale_seconds: 30,
        })
        .is_err());
    }

    #[test]
    fn parses_nft_counter_document() {
        let document: NftDocument = serde_json::from_str(
            r#"{"nftables":[{"counter":{"name":"isop_a_b","packets":2,"bytes":40}}]}"#,
        )
        .unwrap();
        let counter = document.nftables[0].counter.as_ref().unwrap();
        assert_eq!(counter.packets, 2);
        assert_eq!(counter.bytes, 40);
    }

    #[test]
    fn stale_check_is_bounded_and_saturating() {
        assert!(!policy_is_stale(&policy(10_000), 30, 9_000));
        assert!(!policy_is_stale(&policy(10_000), 30, 40_000));
        assert!(policy_is_stale(&policy(10_000), 30, 40_001));
        assert!(policy_is_stale(&policy(40_001), 30, 10_000));
    }

    #[test]
    fn fingerprint_ignores_refresh_time_but_not_policy_content() {
        let first = policy(100);
        let mut refreshed = first.clone();
        refreshed.generated_at_unix_ms = 200;
        assert_eq!(
            policy_fingerprint(&first, IsolationMode::Audit),
            policy_fingerprint(&refreshed, IsolationMode::Audit)
        );
        refreshed.participants[0].ipv4_address = "172.30.0.12".parse().unwrap();
        assert_ne!(
            policy_fingerprint(&first, IsolationMode::Audit),
            policy_fingerprint(&refreshed, IsolationMode::Audit)
        );
    }

    #[test]
    fn reports_only_counter_increases() {
        let policy = policy(100);
        let counter = egressy::isolation::pair_counter_name("one-container", "two-container");
        let previous = [(
            counter.clone(),
            CounterValue {
                packets: 2,
                bytes: 20,
            },
        )]
        .into();
        let current = [(
            counter,
            CounterValue {
                packets: 3,
                bytes: 30,
            },
        )]
        .into();
        assert_eq!(
            violation_changes(&policy, &current, &previous),
            vec![ViolationChange {
                source_id: "one".into(),
                destination_id: "two".into(),
                packets: 3,
                bytes: 30,
            }]
        );
        assert!(violation_changes(&policy, &current, &current).is_empty());
    }
}
