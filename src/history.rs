use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{self, SyncSender, TrySendError},
        Arc,
    },
    thread,
    time::Duration,
};

use anyhow::{bail, Context};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};

use crate::{
    config::PersistenceConfig,
    domain::{PortForwardPhase, Transition, VpnServerLatencyStatus},
    state::UsageIdentitySource,
};

const SCHEMA_VERSION: i64 = 3;
const MAX_SAFE_TEXT: usize = 512;
pub const MAX_USAGE_QUERY_RANGE_MS: u64 = 366 * 86_400_000;

#[derive(Debug, thiserror::Error)]
pub enum HistoryQueryError {
    #[error("{0}")]
    Invalid(String),
    #[error("history storage is unavailable")]
    Unavailable(#[source] anyhow::Error),
}

#[derive(Clone)]
pub struct HistoryStore {
    path: Arc<PathBuf>,
    sender: SyncSender<WriteCommand>,
    dropped_writes: Arc<AtomicU64>,
    bucket_ms: u64,
}

#[derive(Clone, Debug)]
pub struct UsageObservation {
    pub sampled_at_unix_ms: u64,
    pub usage_id: String,
    pub usage_id_source: UsageIdentitySource,
    pub container_id: String,
    pub ipv4_address: String,
    pub name: String,
    pub download_bytes: u64,
    pub upload_bytes: u64,
    pub download_packets: u64,
    pub upload_packets: u64,
}

#[derive(Clone, Debug)]
pub struct PortForwardObservation {
    pub timestamp_unix_ms: u64,
    pub phase: PortForwardPhase,
    pub external_port: Option<u16>,
}

#[derive(Clone, Debug)]
pub struct VpnServerObservation {
    pub timestamp_unix_ms: u64,
    pub configured_endpoint_host: String,
    pub runtime_endpoint_address: String,
    pub runtime_endpoint_port: u16,
    pub active: bool,
    pub latency_status: VpnServerLatencyStatus,
    pub rtt_ms: Option<f64>,
}

enum WriteCommand {
    Usage(UsageObservation, u64),
    Transition(Transition),
    PortForward(PortForwardObservation),
    VpnServer(VpnServerObservation),
    Flush(mpsc::Sender<anyhow::Result<()>>),
    Shutdown(mpsc::Sender<anyhow::Result<()>>),
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct UsageHistoryQuery {
    pub from_unix_ms: Option<u64>,
    pub to_unix_ms: Option<u64>,
    pub bucket_seconds: Option<u64>,
    pub usage_id: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct UsageHistoryPoint {
    pub bucket_start_unix_ms: u64,
    pub usage_id: String,
    pub usage_id_source: UsageIdentitySource,
    pub name: String,
    pub download_bytes: u64,
    pub upload_bytes: u64,
    pub download_packets: u64,
    pub upload_packets: u64,
    pub sample_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct UsageHistoryResponse {
    pub from_unix_ms: u64,
    pub to_unix_ms: u64,
    pub bucket_seconds: u64,
    pub points: Vec<UsageHistoryPoint>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct EventHistoryQuery {
    pub from_unix_ms: Option<u64>,
    pub to_unix_ms: Option<u64>,
    pub before_id: Option<u64>,
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HistoricalEvent {
    pub id: u64,
    pub timestamp_unix_ms: u64,
    pub kind: String,
    pub component: String,
    pub from_status: Option<String>,
    pub to_status: Option<String>,
    pub reason_code: String,
    pub safe_message: String,
    pub external_port: Option<u16>,
    pub port_forward_phase: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EventHistoryResponse {
    pub events: Vec<HistoricalEvent>,
    pub next_before_id: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct VpnServerHistoryQuery {
    pub from_unix_ms: Option<u64>,
    pub to_unix_ms: Option<u64>,
    pub bucket_seconds: Option<u64>,
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct VpnServerHistoryPoint {
    pub bucket_start_unix_ms: u64,
    pub configured_endpoint_host: String,
    pub runtime_endpoint_address: String,
    pub runtime_endpoint_port: u16,
    pub active_sample_count: u64,
    pub sample_count: u64,
    pub measured_sample_count: u64,
    pub minimum_rtt_ms: Option<f64>,
    pub average_rtt_ms: Option<f64>,
    pub maximum_rtt_ms: Option<f64>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct VpnServerHistoryResponse {
    pub from_unix_ms: u64,
    pub to_unix_ms: u64,
    pub bucket_seconds: u64,
    pub points: Vec<VpnServerHistoryPoint>,
    pub truncated: bool,
}

impl HistoryStore {
    pub fn open(config: &PersistenceConfig) -> anyhow::Result<Self> {
        let path = PathBuf::from(&config.path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating history directory {}", parent.display()))?;
        }
        let (sender, receiver) = mpsc::sync_channel(config.writer_capacity);
        let (started_sender, started_receiver) = mpsc::channel();
        let writer_path = path.clone();
        let retention_days = config.retention_days;
        thread::Builder::new()
            .name("egressy-history".to_owned())
            .spawn(move || {
                let result = open_connection(&writer_path).and_then(|connection| {
                    prune(&connection, retention_days)?;
                    started_sender
                        .send(Ok(()))
                        .map_err(|_| anyhow::anyhow!("history startup receiver closed"))?;
                    writer_loop(connection, receiver, retention_days)
                });
                if let Err(error) = result {
                    let _ = started_sender.send(Err(error));
                }
            })
            .context("spawning history writer")?;
        started_receiver
            .recv_timeout(Duration::from_secs(5))
            .context("history writer did not initialize")??;
        Ok(Self {
            path: Arc::new(path),
            sender,
            dropped_writes: Arc::new(AtomicU64::new(0)),
            bucket_ms: config.bucket_seconds.saturating_mul(1_000),
        })
    }

    pub fn record_usage(&self, observation: UsageObservation) -> bool {
        self.try_send(WriteCommand::Usage(observation, self.bucket_ms))
    }

    pub fn record_transition(&self, transition: Transition) -> bool {
        self.try_send(WriteCommand::Transition(transition))
    }

    pub fn record_port_forward(&self, observation: PortForwardObservation) -> bool {
        self.try_send(WriteCommand::PortForward(observation))
    }

    pub fn record_vpn_server(&self, observation: VpnServerObservation) -> bool {
        self.try_send(WriteCommand::VpnServer(observation))
    }

    fn try_send(&self, command: WriteCommand) -> bool {
        match self.sender.try_send(command) {
            Ok(()) => true,
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.dropped_writes.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    pub fn dropped_writes(&self) -> u64 {
        self.dropped_writes.load(Ordering::Relaxed)
    }

    pub async fn flush(&self) -> anyhow::Result<()> {
        self.barrier(false).await
    }

    pub async fn shutdown(&self) -> anyhow::Result<()> {
        self.barrier(true).await
    }

    async fn barrier(&self, shutdown: bool) -> anyhow::Result<()> {
        let sender = self.sender.clone();
        tokio::task::spawn_blocking(move || {
            let (reply_sender, reply_receiver) = mpsc::channel();
            if shutdown {
                sender.send(WriteCommand::Shutdown(reply_sender))?;
            } else {
                sender.send(WriteCommand::Flush(reply_sender))?;
            }
            reply_receiver
                .recv_timeout(Duration::from_secs(5))
                .context("history writer flush timed out")?
        })
        .await
        .context("history flush worker panicked")?
    }

    pub async fn usage_history(
        &self,
        query: UsageHistoryQuery,
    ) -> Result<UsageHistoryResponse, HistoryQueryError> {
        validate_usage_query(self.bucket_ms, &query).map_err(HistoryQueryError::Invalid)?;
        let path = self.path.clone();
        let default_bucket_ms = self.bucket_ms;
        tokio::task::spawn_blocking(move || query_usage(&path, default_bucket_ms, query))
            .await
            .context("usage history query panicked")
            .and_then(|result| result)
            .map_err(HistoryQueryError::Unavailable)
    }

    pub async fn event_history(
        &self,
        query: EventHistoryQuery,
    ) -> Result<EventHistoryResponse, HistoryQueryError> {
        validate_event_query(&query).map_err(HistoryQueryError::Invalid)?;
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || query_events(&path, query))
            .await
            .context("event history query panicked")
            .and_then(|result| result)
            .map_err(HistoryQueryError::Unavailable)
    }

    pub async fn vpn_server_history(
        &self,
        query: VpnServerHistoryQuery,
    ) -> Result<VpnServerHistoryResponse, HistoryQueryError> {
        validate_vpn_server_query(self.bucket_ms, &query).map_err(HistoryQueryError::Invalid)?;
        let path = self.path.clone();
        let default_bucket_ms = self.bucket_ms;
        tokio::task::spawn_blocking(move || query_vpn_server(&path, default_bucket_ms, query))
            .await
            .context("VPN-server history query panicked")
            .and_then(|result| result)
            .map_err(HistoryQueryError::Unavailable)
    }

    pub async fn notification_settings(
        &self,
    ) -> anyhow::Result<crate::notifications::NotificationSettings> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || read_notification_settings(&path))
            .await
            .context("notification settings query panicked")?
    }

    pub async fn save_notification_settings(
        &self,
        settings: crate::notifications::NotificationSettings,
    ) -> anyhow::Result<()> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || write_notification_settings(&path, &settings))
            .await
            .context("notification settings write panicked")?
    }
}

fn normalized_range(
    from: Option<u64>,
    to: Option<u64>,
    default_range_ms: u64,
    label: &str,
) -> Result<(u64, u64), String> {
    let now = crate::runtime::unix_ms();
    let to = to.unwrap_or(now).min(now.saturating_add(60_000));
    let from = from.unwrap_or_else(|| to.saturating_sub(default_range_ms));
    if from >= to || to - from > MAX_USAGE_QUERY_RANGE_MS {
        return Err(format!(
            "{label} range must be positive and no longer than 366 days"
        ));
    }
    Ok((from, to))
}

fn validate_bucket(default_bucket_ms: u64, bucket_seconds: Option<u64>) -> Result<(), String> {
    let bucket_ms = bucket_seconds
        .unwrap_or(default_bucket_ms / 1_000)
        .saturating_mul(1_000);
    if bucket_ms < default_bucket_ms || !bucket_ms.is_multiple_of(default_bucket_ms) {
        return Err("bucket_seconds must be a multiple of the configured storage bucket".into());
    }
    Ok(())
}

fn validate_usage_query(default_bucket_ms: u64, query: &UsageHistoryQuery) -> Result<(), String> {
    normalized_range(query.from_unix_ms, query.to_unix_ms, 86_400_000, "history")?;
    validate_bucket(default_bucket_ms, query.bucket_seconds)
}

fn validate_event_query(query: &EventHistoryQuery) -> Result<(), String> {
    normalized_range(
        query.from_unix_ms,
        query.to_unix_ms,
        30 * 86_400_000,
        "event",
    )?;
    Ok(())
}

fn validate_vpn_server_query(
    default_bucket_ms: u64,
    query: &VpnServerHistoryQuery,
) -> Result<(), String> {
    normalized_range(
        query.from_unix_ms,
        query.to_unix_ms,
        86_400_000,
        "VPN-server history",
    )?;
    validate_bucket(default_bucket_ms, query.bucket_seconds)
}

fn open_connection(path: &Path) -> anyhow::Result<Connection> {
    let mut connection = Connection::open(path)
        .with_context(|| format!("opening history database {}", path.display()))?;
    connection.busy_timeout(Duration::from_secs(2))?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "NORMAL")?;
    migrate(&mut connection)?;
    secure_database_files(path)?;
    Ok(connection)
}

fn secure_database_files(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for candidate in [
            path.to_path_buf(),
            PathBuf::from(format!("{}-wal", path.display())),
            PathBuf::from(format!("{}-shm", path.display())),
        ] {
            if candidate.exists() {
                std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o600))
                    .with_context(|| {
                        format!("securing history database file {}", candidate.display())
                    })?;
            }
        }
    }
    Ok(())
}

fn migrate(connection: &mut Connection) -> anyhow::Result<()> {
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version > SCHEMA_VERSION {
        bail!("history database schema {version} is newer than supported {SCHEMA_VERSION}");
    }
    if version == 0 {
        let transaction = connection.transaction()?;
        transaction.execute_batch(
            "CREATE TABLE usage_buckets (
                bucket_start_ms INTEGER NOT NULL,
                usage_id TEXT NOT NULL,
                usage_id_source TEXT NOT NULL,
                container_id TEXT NOT NULL,
                name TEXT NOT NULL,
                download_bytes INTEGER NOT NULL,
                upload_bytes INTEGER NOT NULL,
                download_packets INTEGER NOT NULL,
                upload_packets INTEGER NOT NULL,
                sample_count INTEGER NOT NULL,
                last_sample_ms INTEGER NOT NULL,
                PRIMARY KEY (bucket_start_ms, usage_id)
             ) WITHOUT ROWID;
             CREATE INDEX usage_buckets_usage_time
                ON usage_buckets (usage_id, bucket_start_ms);
             CREATE TABLE counter_baselines (
                container_id TEXT PRIMARY KEY,
                usage_id TEXT NOT NULL,
                ipv4_address TEXT NOT NULL,
                download_bytes INTEGER NOT NULL,
                upload_bytes INTEGER NOT NULL,
                download_packets INTEGER NOT NULL,
                upload_packets INTEGER NOT NULL,
                last_sample_ms INTEGER NOT NULL
             ) WITHOUT ROWID;
             CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_ms INTEGER NOT NULL,
                kind TEXT NOT NULL,
                component TEXT NOT NULL,
                from_status TEXT,
                to_status TEXT,
                reason_code TEXT NOT NULL,
                safe_message TEXT NOT NULL,
                external_port INTEGER,
                port_forward_phase TEXT
             );
             CREATE INDEX events_time ON events (timestamp_ms, id);
             CREATE TABLE vpn_server_samples (
                timestamp_ms INTEGER PRIMARY KEY,
                configured_endpoint_host TEXT NOT NULL,
                runtime_endpoint_address TEXT NOT NULL,
                runtime_endpoint_port INTEGER NOT NULL,
                active INTEGER NOT NULL,
                latency_status TEXT NOT NULL,
                rtt_ms REAL
             ) WITHOUT ROWID;
             CREATE TABLE notification_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                enabled INTEGER NOT NULL,
                provider TEXT NOT NULL,
                webhook_url TEXT,
                telegram_chat_id TEXT,
                hmac_secret TEXT,
                timeout_seconds INTEGER NOT NULL,
                rtt_threshold_ms REAL NOT NULL,
                alert_stack_started INTEGER NOT NULL,
                alert_vpn_disconnected INTEGER NOT NULL,
                alert_vpn_reconnected INTEGER NOT NULL,
                alert_rtt_above_threshold INTEGER NOT NULL,
                alert_diagnostic_failed INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL
             );
             PRAGMA user_version = 3;",
        )?;
        transaction.commit()?;
    } else if version == 1 {
        let transaction = connection.transaction()?;
        transaction.execute_batch(
            "CREATE TABLE vpn_server_samples (
                timestamp_ms INTEGER PRIMARY KEY,
                configured_endpoint_host TEXT NOT NULL,
                runtime_endpoint_address TEXT NOT NULL,
                runtime_endpoint_port INTEGER NOT NULL,
                active INTEGER NOT NULL,
                latency_status TEXT NOT NULL,
                rtt_ms REAL
             ) WITHOUT ROWID;
             PRAGMA user_version = 2;",
        )?;
        transaction.commit()?;
    }
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == 2 {
        let transaction = connection.transaction()?;
        transaction.execute_batch(
            "CREATE TABLE notification_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                enabled INTEGER NOT NULL,
                provider TEXT NOT NULL,
                webhook_url TEXT,
                telegram_chat_id TEXT,
                hmac_secret TEXT,
                timeout_seconds INTEGER NOT NULL,
                rtt_threshold_ms REAL NOT NULL,
                alert_stack_started INTEGER NOT NULL,
                alert_vpn_disconnected INTEGER NOT NULL,
                alert_vpn_reconnected INTEGER NOT NULL,
                alert_rtt_above_threshold INTEGER NOT NULL,
                alert_diagnostic_failed INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL
             );
             PRAGMA user_version = 3;",
        )?;
        transaction.commit()?;
    }
    Ok(())
}

fn read_notification_settings(
    path: &Path,
) -> anyhow::Result<crate::notifications::NotificationSettings> {
    let connection = open_connection(path)?;
    connection
        .query_row(
            "SELECT enabled, provider, webhook_url, telegram_chat_id, hmac_secret,
                    timeout_seconds, rtt_threshold_ms, alert_stack_started,
                    alert_vpn_disconnected, alert_vpn_reconnected,
                    alert_rtt_above_threshold, alert_diagnostic_failed, updated_at_ms
             FROM notification_settings WHERE id = 1",
            [],
            |row| {
                Ok(crate::notifications::NotificationSettings {
                    enabled: row.get(0)?,
                    provider: crate::notifications::NotificationProvider::from_database(
                        &row.get::<_, String>(1)?,
                    ),
                    webhook_url: row.get(2)?,
                    telegram_chat_id: row.get(3)?,
                    hmac_secret: row.get(4)?,
                    timeout_seconds: row.get::<_, u32>(5)?,
                    rtt_threshold_ms: row.get(6)?,
                    alert_stack_started: row.get(7)?,
                    alert_vpn_disconnected: row.get(8)?,
                    alert_vpn_reconnected: row.get(9)?,
                    alert_rtt_above_threshold: row.get(10)?,
                    alert_diagnostic_failed: row.get(11)?,
                    updated_at_unix_ms: row.get(12)?,
                })
            },
        )
        .optional()
        .map(|settings| settings.unwrap_or_default())
        .context("reading notification settings")
}

fn write_notification_settings(
    path: &Path,
    settings: &crate::notifications::NotificationSettings,
) -> anyhow::Result<()> {
    let connection = open_connection(path)?;
    connection.execute(
        "INSERT INTO notification_settings (
            id, enabled, provider, webhook_url, telegram_chat_id, hmac_secret,
            timeout_seconds, rtt_threshold_ms, alert_stack_started,
            alert_vpn_disconnected, alert_vpn_reconnected,
            alert_rtt_above_threshold, alert_diagnostic_failed, updated_at_ms
         ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
         ON CONFLICT(id) DO UPDATE SET
            enabled = excluded.enabled, provider = excluded.provider,
            webhook_url = excluded.webhook_url,
            telegram_chat_id = excluded.telegram_chat_id,
            hmac_secret = excluded.hmac_secret,
            timeout_seconds = excluded.timeout_seconds,
            rtt_threshold_ms = excluded.rtt_threshold_ms,
            alert_stack_started = excluded.alert_stack_started,
            alert_vpn_disconnected = excluded.alert_vpn_disconnected,
            alert_vpn_reconnected = excluded.alert_vpn_reconnected,
            alert_rtt_above_threshold = excluded.alert_rtt_above_threshold,
            alert_diagnostic_failed = excluded.alert_diagnostic_failed,
            updated_at_ms = excluded.updated_at_ms",
        params![
            settings.enabled,
            settings.provider.as_database(),
            settings.webhook_url,
            settings.telegram_chat_id,
            settings.hmac_secret,
            settings.timeout_seconds,
            settings.rtt_threshold_ms,
            settings.alert_stack_started,
            settings.alert_vpn_disconnected,
            settings.alert_vpn_reconnected,
            settings.alert_rtt_above_threshold,
            settings.alert_diagnostic_failed,
            settings.updated_at_unix_ms,
        ],
    )?;
    secure_database_files(path)
}

fn writer_loop(
    mut connection: Connection,
    receiver: mpsc::Receiver<WriteCommand>,
    retention_days: u32,
) -> anyhow::Result<()> {
    let mut commands_since_prune = 0_u64;
    while let Ok(command) = receiver.recv() {
        match command {
            WriteCommand::Usage(observation, bucket_ms) => {
                write_usage(&mut connection, &observation, bucket_ms)?
            }
            WriteCommand::Transition(transition) => write_transition(&connection, &transition)?,
            WriteCommand::PortForward(observation) => {
                write_port_forward(&connection, &observation)?
            }
            WriteCommand::VpnServer(observation) => write_vpn_server(&connection, &observation)?,
            WriteCommand::Flush(reply) => {
                let result = checkpoint(&connection);
                let _ = reply.send(result);
                continue;
            }
            WriteCommand::Shutdown(reply) => {
                let result = checkpoint(&connection);
                let _ = reply.send(result);
                return Ok(());
            }
        }
        commands_since_prune += 1;
        if commands_since_prune >= 10_000 {
            let transaction = connection.transaction()?;
            prune_transaction(&transaction, retention_days)?;
            transaction.commit()?;
            commands_since_prune = 0;
        }
    }
    Ok(())
}

fn write_usage(
    connection: &mut Connection,
    observation: &UsageObservation,
    bucket_ms: u64,
) -> anyhow::Result<()> {
    let transaction = connection.transaction()?;
    let previous = transaction
        .query_row(
            "SELECT usage_id, ipv4_address, download_bytes, upload_bytes,
                    download_packets, upload_packets
             FROM counter_baselines WHERE container_id = ?1",
            [bounded(&observation.container_id)],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    from_i64(row.get(2)?),
                    from_i64(row.get(3)?),
                    from_i64(row.get(4)?),
                    from_i64(row.get(5)?),
                ))
            },
        )
        .optional()?;
    let same_incarnation = previous.as_ref().is_some_and(|(usage_id, address, ..)| {
        usage_id == &observation.usage_id && address == &observation.ipv4_address
    });
    let (download_bytes, upload_bytes, download_packets, upload_packets) = if let Some((
        _,
        _,
        previous_download_bytes,
        previous_upload_bytes,
        previous_download_packets,
        previous_upload_packets,
    )) =
        previous.filter(|_| same_incarnation)
    {
        (
            monotonic_delta(observation.download_bytes, previous_download_bytes),
            monotonic_delta(observation.upload_bytes, previous_upload_bytes),
            monotonic_delta(observation.download_packets, previous_download_packets),
            monotonic_delta(observation.upload_packets, previous_upload_packets),
        )
    } else {
        (
            observation.download_bytes,
            observation.upload_bytes,
            observation.download_packets,
            observation.upload_packets,
        )
    };
    transaction.execute(
        "INSERT INTO counter_baselines (
            container_id, usage_id, ipv4_address, download_bytes, upload_bytes,
            download_packets, upload_packets, last_sample_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(container_id) DO UPDATE SET
            usage_id = excluded.usage_id,
            ipv4_address = excluded.ipv4_address,
            download_bytes = excluded.download_bytes,
            upload_bytes = excluded.upload_bytes,
            download_packets = excluded.download_packets,
            upload_packets = excluded.upload_packets,
            last_sample_ms = excluded.last_sample_ms",
        params![
            bounded(&observation.container_id),
            bounded(&observation.usage_id),
            bounded(&observation.ipv4_address),
            to_i64(observation.download_bytes),
            to_i64(observation.upload_bytes),
            to_i64(observation.download_packets),
            to_i64(observation.upload_packets),
            to_i64(observation.sampled_at_unix_ms),
        ],
    )?;
    if download_bytes == 0 && upload_bytes == 0 && download_packets == 0 && upload_packets == 0 {
        transaction.commit()?;
        return Ok(());
    }
    let bucket_start = observation.sampled_at_unix_ms - observation.sampled_at_unix_ms % bucket_ms;
    transaction.execute(
        "INSERT INTO usage_buckets (
            bucket_start_ms, usage_id, usage_id_source, container_id, name,
            download_bytes, upload_bytes, download_packets, upload_packets,
            sample_count, last_sample_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, ?10)
         ON CONFLICT(bucket_start_ms, usage_id) DO UPDATE SET
            usage_id_source = excluded.usage_id_source,
            container_id = excluded.container_id,
            name = excluded.name,
            download_bytes = MIN(9223372036854775807, download_bytes + excluded.download_bytes),
            upload_bytes = MIN(9223372036854775807, upload_bytes + excluded.upload_bytes),
            download_packets = MIN(9223372036854775807, download_packets + excluded.download_packets),
            upload_packets = MIN(9223372036854775807, upload_packets + excluded.upload_packets),
            sample_count = sample_count + 1,
            last_sample_ms = excluded.last_sample_ms",
        params![
            to_i64(bucket_start),
            bounded(&observation.usage_id),
            usage_source(observation.usage_id_source),
            bounded(&observation.container_id),
            bounded(&observation.name),
            to_i64(download_bytes),
            to_i64(upload_bytes),
            to_i64(download_packets),
            to_i64(upload_packets),
            to_i64(observation.sampled_at_unix_ms),
        ],
    )?;
    transaction.commit()?;
    Ok(())
}

fn write_transition(connection: &Connection, transition: &Transition) -> anyhow::Result<()> {
    connection.execute(
        "INSERT INTO events (
            timestamp_ms, kind, component, from_status, to_status, reason_code, safe_message
         ) VALUES (?1, 'transition', ?2, ?3, ?4, ?5, ?6)",
        params![
            to_i64(transition.timestamp_unix_ms),
            bounded(&transition.component),
            enum_json(&transition.from_status),
            enum_json(&transition.to_status),
            bounded(&transition.reason_code),
            bounded(&transition.safe_message),
        ],
    )?;
    Ok(())
}

fn write_port_forward(
    connection: &Connection,
    observation: &PortForwardObservation,
) -> anyhow::Result<()> {
    let phase = enum_json(&observation.phase);
    let message = match observation.external_port {
        Some(port) => format!("Forwarded-port lifecycle changed to {phase} on port {port}"),
        None => format!("Forwarded-port lifecycle changed to {phase}"),
    };
    connection.execute(
        "INSERT INTO events (
            timestamp_ms, kind, component, reason_code, safe_message,
            external_port, port_forward_phase
         ) VALUES (?1, 'port_forward', 'port_forward', 'port_forward.lifecycle_changed', ?2, ?3, ?4)",
        params![
            to_i64(observation.timestamp_unix_ms),
            message,
            observation.external_port,
            phase,
        ],
    )?;
    Ok(())
}

fn write_vpn_server(
    connection: &Connection,
    observation: &VpnServerObservation,
) -> anyhow::Result<()> {
    connection.execute(
        "INSERT OR REPLACE INTO vpn_server_samples (
            timestamp_ms, configured_endpoint_host, runtime_endpoint_address,
            runtime_endpoint_port, active, latency_status, rtt_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            to_i64(observation.timestamp_unix_ms),
            bounded(&observation.configured_endpoint_host),
            bounded(&observation.runtime_endpoint_address),
            observation.runtime_endpoint_port,
            observation.active,
            enum_json(&observation.latency_status),
            observation.rtt_ms,
        ],
    )?;
    Ok(())
}

fn prune(connection: &Connection, retention_days: u32) -> anyhow::Result<()> {
    let cutoff = crate::runtime::unix_ms()
        .saturating_sub(u64::from(retention_days).saturating_mul(86_400_000));
    connection.execute(
        "DELETE FROM usage_buckets WHERE bucket_start_ms < ?1",
        [to_i64(cutoff)],
    )?;
    connection.execute(
        "DELETE FROM events WHERE timestamp_ms < ?1",
        [to_i64(cutoff)],
    )?;
    connection.execute(
        "DELETE FROM counter_baselines WHERE last_sample_ms < ?1",
        [to_i64(cutoff)],
    )?;
    connection.execute(
        "DELETE FROM vpn_server_samples WHERE timestamp_ms < ?1",
        [to_i64(cutoff)],
    )?;
    Ok(())
}

fn prune_transaction(transaction: &Transaction<'_>, retention_days: u32) -> anyhow::Result<()> {
    let cutoff = crate::runtime::unix_ms()
        .saturating_sub(u64::from(retention_days).saturating_mul(86_400_000));
    transaction.execute(
        "DELETE FROM usage_buckets WHERE bucket_start_ms < ?1",
        [to_i64(cutoff)],
    )?;
    transaction.execute(
        "DELETE FROM events WHERE timestamp_ms < ?1",
        [to_i64(cutoff)],
    )?;
    transaction.execute(
        "DELETE FROM counter_baselines WHERE last_sample_ms < ?1",
        [to_i64(cutoff)],
    )?;
    transaction.execute(
        "DELETE FROM vpn_server_samples WHERE timestamp_ms < ?1",
        [to_i64(cutoff)],
    )?;
    Ok(())
}

fn checkpoint(connection: &Connection) -> anyhow::Result<()> {
    connection.execute_batch("PRAGMA wal_checkpoint(PASSIVE)")?;
    Ok(())
}

fn query_usage(
    path: &Path,
    default_bucket_ms: u64,
    query: UsageHistoryQuery,
) -> anyhow::Result<UsageHistoryResponse> {
    let now = crate::runtime::unix_ms();
    let to = query
        .to_unix_ms
        .unwrap_or(now)
        .min(now.saturating_add(60_000));
    let from = query
        .from_unix_ms
        .unwrap_or_else(|| to.saturating_sub(86_400_000));
    if from >= to || to - from > MAX_USAGE_QUERY_RANGE_MS {
        bail!("history range must be positive and no longer than 366 days");
    }
    let bucket_ms = query
        .bucket_seconds
        .unwrap_or(default_bucket_ms / 1_000)
        .saturating_mul(1_000);
    if bucket_ms < default_bucket_ms || !bucket_ms.is_multiple_of(default_bucket_ms) {
        bail!("bucket_seconds must be a multiple of the configured storage bucket");
    }
    let limit = query.limit.unwrap_or(5_000).clamp(1, 10_000);
    let connection = open_connection(path)?;
    let mut statement = connection.prepare(
        "SELECT
            (bucket_start_ms / ?1) * ?1 AS grouped_bucket,
            usage_id,
            MAX(usage_id_source),
            MAX(name),
            SUM(download_bytes), SUM(upload_bytes),
            SUM(download_packets), SUM(upload_packets), SUM(sample_count)
         FROM usage_buckets
         WHERE bucket_start_ms >= ?2 AND bucket_start_ms < ?3
           AND (?4 IS NULL OR usage_id = ?4)
         GROUP BY grouped_bucket, usage_id
         ORDER BY grouped_bucket ASC, usage_id ASC
         LIMIT ?5",
    )?;
    let usage_id = query.usage_id.as_deref();
    let mut rows = statement.query(params![
        to_i64(bucket_ms),
        to_i64(from),
        to_i64(to),
        usage_id,
        i64::try_from(limit + 1).unwrap_or(i64::MAX),
    ])?;
    let mut points = Vec::new();
    while let Some(row) = rows.next()? {
        points.push(UsageHistoryPoint {
            bucket_start_unix_ms: from_i64(row.get(0)?),
            usage_id: row.get(1)?,
            usage_id_source: parse_usage_source(&row.get::<_, String>(2)?),
            name: row.get(3)?,
            download_bytes: from_i64(row.get(4)?),
            upload_bytes: from_i64(row.get(5)?),
            download_packets: from_i64(row.get(6)?),
            upload_packets: from_i64(row.get(7)?),
            sample_count: from_i64(row.get(8)?),
        });
    }
    let truncated = points.len() > limit;
    points.truncate(limit);
    Ok(UsageHistoryResponse {
        from_unix_ms: from,
        to_unix_ms: to,
        bucket_seconds: bucket_ms / 1_000,
        points,
        truncated,
    })
}

fn query_events(path: &Path, query: EventHistoryQuery) -> anyhow::Result<EventHistoryResponse> {
    let now = crate::runtime::unix_ms();
    let to = query
        .to_unix_ms
        .unwrap_or(now)
        .min(now.saturating_add(60_000));
    let from = query
        .from_unix_ms
        .unwrap_or_else(|| to.saturating_sub(30 * 86_400_000));
    if from >= to || to - from > MAX_USAGE_QUERY_RANGE_MS {
        bail!("event range must be positive and no longer than 366 days");
    }
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let before = query.before_id.unwrap_or(u64::MAX);
    let connection = open_connection(path)?;
    let mut statement = connection.prepare(
        "SELECT id, timestamp_ms, kind, component, from_status, to_status,
                reason_code, safe_message, external_port, port_forward_phase
         FROM events
         WHERE timestamp_ms >= ?1 AND timestamp_ms < ?2 AND id < ?3
         ORDER BY id DESC
         LIMIT ?4",
    )?;
    let mut rows = statement.query(params![
        to_i64(from),
        to_i64(to),
        to_i64(before),
        i64::try_from(limit + 1).unwrap_or(i64::MAX),
    ])?;
    let mut events = Vec::new();
    while let Some(row) = rows.next()? {
        events.push(HistoricalEvent {
            id: from_i64(row.get(0)?),
            timestamp_unix_ms: from_i64(row.get(1)?),
            kind: row.get(2)?,
            component: row.get(3)?,
            from_status: row.get(4)?,
            to_status: row.get(5)?,
            reason_code: row.get(6)?,
            safe_message: row.get(7)?,
            external_port: row.get(8)?,
            port_forward_phase: row.get(9)?,
        });
    }
    let has_more = events.len() > limit;
    events.truncate(limit);
    let next_before_id = has_more
        .then(|| events.last().map(|event| event.id))
        .flatten();
    Ok(EventHistoryResponse {
        events,
        next_before_id,
    })
}

fn query_vpn_server(
    path: &Path,
    default_bucket_ms: u64,
    query: VpnServerHistoryQuery,
) -> anyhow::Result<VpnServerHistoryResponse> {
    let now = crate::runtime::unix_ms();
    let to = query
        .to_unix_ms
        .unwrap_or(now)
        .min(now.saturating_add(60_000));
    let from = query
        .from_unix_ms
        .unwrap_or_else(|| to.saturating_sub(86_400_000));
    if from >= to || to - from > MAX_USAGE_QUERY_RANGE_MS {
        bail!("VPN-server history range must be positive and no longer than 366 days");
    }
    let bucket_ms = query
        .bucket_seconds
        .unwrap_or(default_bucket_ms / 1_000)
        .saturating_mul(1_000);
    if bucket_ms < default_bucket_ms || !bucket_ms.is_multiple_of(default_bucket_ms) {
        bail!("bucket_seconds must be a multiple of the configured storage bucket");
    }
    let limit = query.limit.unwrap_or(5_000).clamp(1, 10_000);
    let connection = open_connection(path)?;
    let mut statement = connection.prepare(
        "SELECT
            (timestamp_ms / ?1) * ?1 AS grouped_bucket,
            MAX(configured_endpoint_host), MAX(runtime_endpoint_address),
            MAX(runtime_endpoint_port), SUM(active), COUNT(*), COUNT(rtt_ms),
            MIN(rtt_ms), AVG(rtt_ms), MAX(rtt_ms)
         FROM vpn_server_samples
         WHERE timestamp_ms >= ?2 AND timestamp_ms < ?3
         GROUP BY grouped_bucket
         ORDER BY grouped_bucket ASC
         LIMIT ?4",
    )?;
    let mut rows = statement.query(params![
        to_i64(bucket_ms),
        to_i64(from),
        to_i64(to),
        i64::try_from(limit + 1).unwrap_or(i64::MAX),
    ])?;
    let mut points = Vec::new();
    while let Some(row) = rows.next()? {
        points.push(VpnServerHistoryPoint {
            bucket_start_unix_ms: from_i64(row.get(0)?),
            configured_endpoint_host: row.get(1)?,
            runtime_endpoint_address: row.get(2)?,
            runtime_endpoint_port: row.get(3)?,
            active_sample_count: from_i64(row.get(4)?),
            sample_count: from_i64(row.get(5)?),
            measured_sample_count: from_i64(row.get(6)?),
            minimum_rtt_ms: row.get(7)?,
            average_rtt_ms: row.get(8)?,
            maximum_rtt_ms: row.get(9)?,
        });
    }
    let truncated = points.len() > limit;
    points.truncate(limit);
    Ok(VpnServerHistoryResponse {
        from_unix_ms: from,
        to_unix_ms: to,
        bucket_seconds: bucket_ms / 1_000,
        points,
        truncated,
    })
}

fn bounded(value: &str) -> String {
    value.chars().take(MAX_SAFE_TEXT).collect()
}

fn enum_json<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value)
        .unwrap_or_else(|_| "\"unknown\"".to_owned())
        .trim_matches('"')
        .to_owned()
}

fn usage_source(source: UsageIdentitySource) -> &'static str {
    match source {
        UsageIdentitySource::ExplicitLabel => "explicit_label",
        UsageIdentitySource::ComposeService => "compose_service",
        UsageIdentitySource::ContainerLifetime => "container_lifetime",
    }
}

fn parse_usage_source(source: &str) -> UsageIdentitySource {
    match source {
        "explicit_label" => UsageIdentitySource::ExplicitLabel,
        "compose_service" => UsageIdentitySource::ComposeService,
        _ => UsageIdentitySource::ContainerLifetime,
    }
}

fn to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn from_i64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or_default()
}

fn monotonic_delta(current: u64, previous: u64) -> u64 {
    if current >= previous {
        current - previous
    } else {
        current
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::domain::CheckStatus;

    fn test_store(temp: &TempDir) -> HistoryStore {
        HistoryStore::open(&PersistenceConfig {
            path: temp.path().join("history.sqlite3").display().to_string(),
            ..PersistenceConfig::default()
        })
        .unwrap()
    }

    #[tokio::test]
    async fn usage_deltas_are_aggregated_and_survive_reopen() {
        let temp = TempDir::new().unwrap();
        let store = test_store(&temp);
        let now = crate::runtime::unix_ms();
        for bytes in [10, 25] {
            assert!(store.record_usage(UsageObservation {
                sampled_at_unix_ms: now,
                usage_id: "compose:media/qbit".into(),
                usage_id_source: UsageIdentitySource::ComposeService,
                container_id: "container-a".into(),
                ipv4_address: "172.30.0.10".into(),
                name: "qbit".into(),
                download_bytes: bytes,
                upload_bytes: 3,
                download_packets: 1,
                upload_packets: 2,
            }));
        }
        store.flush().await.unwrap();
        let response = store
            .usage_history(UsageHistoryQuery {
                from_unix_ms: Some(now.saturating_sub(60_000)),
                to_unix_ms: Some(now + 60_000),
                usage_id: Some("compose:media/qbit".into()),
                ..UsageHistoryQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(response.points.len(), 1);
        assert_eq!(response.points[0].download_bytes, 25);
        assert_eq!(response.points[0].sample_count, 2);
        store.shutdown().await.unwrap();

        let reopened = test_store(&temp);
        assert!(reopened.record_usage(UsageObservation {
            sampled_at_unix_ms: now + 1_000,
            usage_id: "compose:media/qbit".into(),
            usage_id_source: UsageIdentitySource::ComposeService,
            container_id: "container-a".into(),
            ipv4_address: "172.30.0.10".into(),
            name: "qbit".into(),
            download_bytes: 25,
            upload_bytes: 3,
            download_packets: 1,
            upload_packets: 2,
        }));
        reopened.flush().await.unwrap();
        let response = reopened
            .usage_history(UsageHistoryQuery {
                from_unix_ms: Some(now.saturating_sub(60_000)),
                to_unix_ms: Some(now + 60_000),
                ..UsageHistoryQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(response.points[0].download_bytes, 25);
        reopened.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn transitions_and_port_changes_are_paginated() {
        let temp = TempDir::new().unwrap();
        let store = test_store(&temp);
        assert!(store.record_transition(Transition {
            sequence: 1,
            timestamp_unix_ms: 100_000,
            component: "wireguard.handshake".into(),
            from_status: CheckStatus::Pending,
            to_status: CheckStatus::Healthy,
            reason_code: "wireguard.handshake_recent".into(),
            safe_message: "Recent handshake observed".into(),
            recovery_attempt: None,
        }));
        assert!(store.record_port_forward(PortForwardObservation {
            timestamp_unix_ms: 101_000,
            phase: PortForwardPhase::Installed,
            external_port: Some(45_678),
        }));
        store.flush().await.unwrap();
        let first = store
            .event_history(EventHistoryQuery {
                from_unix_ms: Some(1),
                to_unix_ms: Some(200_000),
                limit: Some(1),
                ..EventHistoryQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(first.events[0].kind, "port_forward");
        assert!(first.next_before_id.is_some());
        let second = store
            .event_history(EventHistoryQuery {
                from_unix_ms: Some(1),
                to_unix_ms: Some(200_000),
                before_id: first.next_before_id,
                limit: Some(1),
            })
            .await
            .unwrap();
        assert_eq!(second.events[0].kind, "transition");
        store.shutdown().await.unwrap();
    }

    #[test]
    fn refuses_unknown_newer_schema() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("future.sqlite3");
        let connection = Connection::open(&path).unwrap();
        connection.pragma_update(None, "user_version", 999).unwrap();
        drop(connection);
        let result = HistoryStore::open(&PersistenceConfig {
            path: path.display().to_string(),
            ..PersistenceConfig::default()
        });
        assert!(result.is_err());
    }

    #[test]
    fn rejects_oversized_query_ranges() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("history.sqlite3");
        open_connection(&path).unwrap();
        let result = query_usage(
            &path,
            60_000,
            UsageHistoryQuery {
                from_unix_ms: Some(1),
                to_unix_ms: Some(MAX_USAGE_QUERY_RANGE_MS + 2),
                ..UsageHistoryQuery::default()
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn retention_removes_expired_rows() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("history.sqlite3");
        let connection = open_connection(&path).unwrap();
        connection
            .execute(
                "INSERT INTO events (timestamp_ms, kind, component, reason_code, safe_message)
                 VALUES (1, 'transition', 'test', 'test.old', 'old')",
                [],
            )
            .unwrap();
        prune(&connection, 1).unwrap();
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn vpn_server_latency_is_persisted_and_bucketed() {
        let temp = TempDir::new().unwrap();
        let store = test_store(&temp);
        let now = crate::runtime::unix_ms();
        for (offset, rtt) in [Some(10.0), None, Some(20.0)].into_iter().enumerate() {
            assert!(store.record_vpn_server(VpnServerObservation {
                timestamp_unix_ms: now + offset as u64,
                configured_endpoint_host: "us-ny.protonvpn.net".into(),
                runtime_endpoint_address: "198.51.100.10".into(),
                runtime_endpoint_port: 51820,
                active: true,
                latency_status: if rtt.is_some() {
                    VpnServerLatencyStatus::Measured
                } else {
                    VpnServerLatencyStatus::Timeout
                },
                rtt_ms: rtt,
            }));
        }
        store.flush().await.unwrap();
        let response = store
            .vpn_server_history(VpnServerHistoryQuery {
                from_unix_ms: Some(now.saturating_sub(60_000)),
                to_unix_ms: Some(now + 60_000),
                ..VpnServerHistoryQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(response.points.len(), 1);
        assert_eq!(response.points[0].sample_count, 3);
        assert_eq!(response.points[0].measured_sample_count, 2);
        assert_eq!(response.points[0].minimum_rtt_ms, Some(10.0));
        assert_eq!(response.points[0].average_rtt_ms, Some(15.0));
        assert_eq!(response.points[0].maximum_rtt_ms, Some(20.0));
        store.shutdown().await.unwrap();
    }

    #[test]
    fn migrates_schema_one_to_three_without_losing_events() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("v1.sqlite3");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp_ms INTEGER NOT NULL,
                    kind TEXT NOT NULL, component TEXT NOT NULL, from_status TEXT,
                    to_status TEXT, reason_code TEXT NOT NULL, safe_message TEXT NOT NULL,
                    external_port INTEGER, port_forward_phase TEXT
                 );
                 CREATE TABLE usage_buckets (
                    bucket_start_ms INTEGER NOT NULL, usage_id TEXT NOT NULL,
                    usage_id_source TEXT NOT NULL, container_id TEXT NOT NULL, name TEXT NOT NULL,
                    download_bytes INTEGER NOT NULL, upload_bytes INTEGER NOT NULL,
                    download_packets INTEGER NOT NULL, upload_packets INTEGER NOT NULL,
                    sample_count INTEGER NOT NULL, last_sample_ms INTEGER NOT NULL,
                    PRIMARY KEY (bucket_start_ms, usage_id)
                 ) WITHOUT ROWID;
                 CREATE TABLE counter_baselines (
                    container_id TEXT PRIMARY KEY, usage_id TEXT NOT NULL,
                    ipv4_address TEXT NOT NULL, download_bytes INTEGER NOT NULL,
                    upload_bytes INTEGER NOT NULL, download_packets INTEGER NOT NULL,
                    upload_packets INTEGER NOT NULL, last_sample_ms INTEGER NOT NULL
                 ) WITHOUT ROWID;
                 INSERT INTO events (timestamp_ms, kind, component, reason_code, safe_message)
                    VALUES (1, 'transition', 'test', 'test.ok', 'safe');
                 PRAGMA user_version = 1;",
            )
            .unwrap();
        drop(connection);
        let mut connection = Connection::open(&path).unwrap();
        migrate(&mut connection).unwrap();
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        let events: i64 = connection
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 3);
        assert_eq!(events, 1);
    }

    #[tokio::test]
    async fn notification_settings_are_persisted_across_reopen() {
        let temp = TempDir::new().unwrap();
        let store = test_store(&temp);
        let settings = crate::notifications::NotificationSettings {
            enabled: true,
            provider: crate::notifications::NotificationProvider::Generic,
            webhook_url: Some("https://example.com/private-hook".into()),
            hmac_secret: Some("test-only-secret".into()),
            updated_at_unix_ms: 123,
            ..crate::notifications::NotificationSettings::default()
        };
        store
            .save_notification_settings(settings.clone())
            .await
            .unwrap();
        assert_eq!(store.notification_settings().await.unwrap(), settings);
        store.shutdown().await.unwrap();

        let reopened = test_store(&temp);
        assert_eq!(reopened.notification_settings().await.unwrap(), settings);
        reopened.shutdown().await.unwrap();
    }

    #[test]
    fn database_does_not_contain_transition_secrets_from_unstored_fields() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("history.sqlite3");
        let connection = open_connection(&path).unwrap();
        let private_key = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE sql LIKE '%PrivateKey%' LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .unwrap();
        assert!(private_key.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn database_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let path = temp.path().join("history.sqlite3");
        let connection = open_connection(&path).unwrap();
        connection
            .execute(
                "CREATE TABLE IF NOT EXISTS permission_probe (id INTEGER)",
                [],
            )
            .unwrap();
        secure_database_files(&path).unwrap();
        for candidate in [
            path.clone(),
            PathBuf::from(format!("{}-wal", path.display())),
            PathBuf::from(format!("{}-shm", path.display())),
        ] {
            if candidate.exists() {
                assert_eq!(
                    std::fs::metadata(candidate).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
    }
}
