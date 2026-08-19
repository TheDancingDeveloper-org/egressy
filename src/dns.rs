use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex as StdMutex,
    },
    time::{Duration, Instant},
};

use anyhow::{bail, Context};
use hickory_proto::op::{Message, MessageType, ResponseCode};
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
    /// An operator-set fixed ceiling per client. `None` derives each client's
    /// bound from the global budget and the number of clients using it.
    pub max_concurrent_queries_per_client: Option<usize>,
    pub udp_attempts: u32,
    pub failure_threshold: u32,
    pub success_threshold: u32,
    pub local_zones_enabled: bool,
    /// Shared response cache, when enabled.
    pub cache: Option<Arc<crate::dns_cache::DnsCache>>,
    /// Enrolled-bridge container names, refreshed by Docker discovery.
    pub local_names: watch::Receiver<Arc<std::collections::BTreeMap<String, std::net::Ipv4Addr>>>,
    pub publisher: Option<StatePublisher>,
}

static LOCAL_ANSWERS: AtomicU64 = AtomicU64::new(0);
static CACHE_HITS: AtomicU64 = AtomicU64::new(0);
static CACHE_MISSES: AtomicU64 = AtomicU64::new(0);

/// A cached response for this query, if one is still live.
///
/// Like local answers, this is attempted before admission control: a hit costs
/// no upstream capacity, so repeated names keep resolving under load.
fn cached_answer(settings: &Settings, query: &[u8]) -> Option<Vec<u8>> {
    let cache = settings.cache.as_ref()?;
    let upstream = (*settings.upstream.borrow())?;
    match cache.lookup(query, upstream, std::time::Instant::now()) {
        Some(response) => {
            CACHE_HITS.fetch_add(1, Ordering::Relaxed);
            Some(response)
        }
        None => {
            CACHE_MISSES.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

fn remember_answer(settings: &Settings, query: &[u8], response: &[u8], upstream: SocketAddr) {
    if let Some(cache) = settings.cache.as_ref() {
        cache.store(query, response, upstream, std::time::Instant::now());
    }
}

/// Answer from the enrolled-bridge name map, if this query is one we own.
///
/// Deliberately attempted before admission control: these answers need no
/// upstream capacity, so internal name resolution keeps working even while the
/// forwarder is saturated.
fn local_answer(settings: &Settings, query: &[u8]) -> Option<Vec<u8>> {
    if !settings.local_zones_enabled {
        return None;
    }
    let names = Arc::clone(&settings.local_names.borrow());
    let response = crate::local_zone::answer(query, &names)?;
    LOCAL_ANSWERS.fetch_add(1, Ordering::Relaxed);
    Some(response)
}

static UDP_QUERIES: AtomicU64 = AtomicU64::new(0);
static UDP_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static UDP_TIMEOUTS: AtomicU64 = AtomicU64::new(0);
static UDP_EXHAUSTED: AtomicU64 = AtomicU64::new(0);
static TCP_FALLBACKS: AtomicU64 = AtomicU64::new(0);
static TCP_FALLBACK_SUCCESSES: AtomicU64 = AtomicU64::new(0);
/// Debounced resolution health as a gauge: 1 healthy, 0 degraded, absent until
/// the first verdict. Exported so a resolver outage is alertable — the
/// container healthcheck probes `/livez`, which reports process liveness only
/// and stays green while every query fails.
static RESOLUTION_HEALTHY: AtomicU64 = AtomicU64::new(u64::MAX);
static QUERIES_REFUSED_GLOBAL: AtomicU64 = AtomicU64::new(0);
static QUERIES_REFUSED_PER_CLIENT: AtomicU64 = AtomicU64::new(0);

/// Admission control for forwarded queries.
///
/// A single global bound is not enough on a shared gateway: one client
/// recovering from an outage can burst hard enough to consume every permit and
/// deny service to every other enrolled client, which is what a real incident
/// produced. Each client therefore also has its own bound, so a noisy neighbour
/// can exhaust its own share and no one else's.
///
/// That bound is a *share* of the global budget rather than a constant. A fixed
/// 64 against a global 512 means the gateway needs eight equally busy clients
/// before the global bound can ever be the one that binds; below that the
/// configured capacity is decorative, and a bridge with one busy client refuses
/// traffic at an eighth of what it was told to allow while 448 permits sit
/// idle. The share is therefore the global budget divided by the clients
/// currently using the forwarder — floored, so a bridge full of quiet clients
/// cannot squeeze a busy one down to nothing, and capped at the global budget,
/// which remains the only bound on total load.
///
/// A share is also only worth enforcing while there is something to compete
/// for. Dividing by the clients *present* still refuses a lone busy client on a
/// gateway whose budget is entirely idle, because the other clients counted in
/// the divisor want almost none of it — 15,175 refusals against a global budget
/// that was never once reached. Admission is therefore work-conserving: above a
/// reserve of free permits a client may borrow the idle capacity, and once the
/// free pool falls to that reserve everyone is held to their share again. The
/// reserve is what keeps a late-arriving client able to claim one, so the
/// anti-starvation property survives.
pub struct QueryPermits {
    global: Arc<Semaphore>,
    global_limit: usize,
    clients: StdMutex<ClientTable>,
    /// An operator-set fixed ceiling, which overrides the derived share.
    fixed_per_client: Option<usize>,
    /// Free global permits below which shares start binding.
    borrow_reserve: usize,
}

/// The floor under a derived share. Below this a client has too little
/// concurrency to resolve at a useful rate, and the global budget is the bound
/// that should be shedding load.
const MIN_CLIENT_SHARE: usize = 64;

/// How long a client counts towards the divisor after its last query.
const CLIENT_IDLE_AFTER: Duration = Duration::from_secs(60);

/// The fraction of the global budget held back from borrowing. Shares bind once
/// free permits fall to this, so capacity is always left for a client that has
/// not asked for anything yet.
const BORROW_RESERVE_DIVISOR: usize = 4;

/// How often idle clients are swept. The divisor changes on the timescale
/// clients arrive and leave, so a stale count for up to this long is harmless
/// and keeps the sweep off the per-query path.
const PRUNE_INTERVAL: Duration = Duration::from_secs(1);

const MAX_TRACKED_CLIENTS: usize = 1_024;

struct ClientTable {
    loads: HashMap<IpAddr, ClientLoad>,
    pruned_at: Instant,
}

struct ClientLoad {
    in_flight: Arc<AtomicUsize>,
    last_seen: Instant,
}

/// Held for the lifetime of a forwarded query.
#[derive(Debug)]
pub struct QueryPermit {
    global: tokio::sync::OwnedSemaphorePermit,
    client: ClientSlot,
}

/// One in-flight query against a client's share, returned when dropped.
#[derive(Debug)]
pub struct ClientSlot(Arc<AtomicUsize>);

impl Drop for ClientSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl QueryPermit {
    /// Separate admission from the work it admitted.
    ///
    /// A client's slot is what refuses traffic, and holding one across the
    /// whole retry ladder is what converted upstream latency into refusals: two
    /// UDP attempts and a TCP fallback can occupy a slot for the better part of
    /// ten seconds, so a slow resolver closed the door in proportion to its own
    /// latency. Dropping the returned slot gives the share back while the query
    /// continues; the global permit still bounds total in-flight work.
    pub fn into_parts(self) -> (tokio::sync::OwnedSemaphorePermit, ClientSlot) {
        (self.global, self.client)
    }
}

/// Why a query was refused, so the two causes stay distinguishable in logs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    GlobalLimit,
    ClientLimit,
}

impl QueryPermits {
    pub fn new(global: usize, per_client: Option<usize>) -> Self {
        let global_limit = global.max(1);
        Self {
            global: Arc::new(Semaphore::new(global_limit)),
            global_limit,
            clients: StdMutex::new(ClientTable {
                loads: HashMap::new(),
                pruned_at: Instant::now(),
            }),
            fixed_per_client: per_client.map(|limit| limit.clamp(1, global_limit)),
            borrow_reserve: (global_limit / BORROW_RESERVE_DIVISOR).max(1),
        }
    }

    pub fn try_acquire(&self, client: IpAddr) -> Result<QueryPermit, Refusal> {
        let (in_flight, active_clients) = self.client_share(client, Instant::now());
        // Take the client's share first: refusing here is the cheaper outcome
        // and keeps a burst from briefly holding global permits.
        let slot =
            claim(&in_flight, self.admission_limit(active_clients)).ok_or(Refusal::ClientLimit)?;
        let global = Arc::clone(&self.global)
            .try_acquire_owned()
            .map_err(|_| Refusal::GlobalLimit)?;
        Ok(QueryPermit {
            global,
            client: slot,
        })
    }

    /// This client's in-flight counter, and how many clients are using the
    /// forwarder right now.
    fn client_share(&self, client: IpAddr, now: Instant) -> (Arc<AtomicUsize>, usize) {
        let mut table = self
            .clients
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        prune(&mut table, now);
        let load = table.loads.entry(client).or_insert_with(|| ClientLoad {
            in_flight: Arc::new(AtomicUsize::new(0)),
            last_seen: now,
        });
        load.last_seen = now;
        let in_flight = Arc::clone(&load.in_flight);
        (in_flight, table.loads.len())
    }

    /// The bound to admit against right now.
    ///
    /// A share describes how capacity is divided when it is scarce. While it is
    /// not scarce there is nobody to divide it from, so a client may use what is
    /// idle; refusing a query the gateway has the capacity to serve buys
    /// nothing. An operator-set ceiling is absolute and never borrows past.
    fn admission_limit(&self, active_clients: usize) -> usize {
        if self.fixed_per_client.is_some() {
            return self.limit_for(active_clients);
        }
        if self.global.available_permits() > self.borrow_reserve {
            return self.global_limit;
        }
        self.limit_for(active_clients)
    }

    #[cfg(test)]
    fn tracked_clients(&self) -> usize {
        self.clients
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .loads
            .len()
    }

    /// The per-client bound when `active_clients` are using the forwarder.
    fn limit_for(&self, active_clients: usize) -> usize {
        if let Some(fixed) = self.fixed_per_client {
            return fixed;
        }
        let share = self.global_limit / active_clients.max(1);
        share.clamp(MIN_CLIENT_SHARE.min(self.global_limit), self.global_limit)
    }
}

/// Take a slot against a client's share, or `None` if the share is full.
fn claim(in_flight: &Arc<AtomicUsize>, limit: usize) -> Option<ClientSlot> {
    let mut current = in_flight.load(Ordering::Acquire);
    loop {
        if current >= limit {
            return None;
        }
        match in_flight.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Some(ClientSlot(Arc::clone(in_flight))),
            Err(observed) => current = observed,
        }
    }
}

/// Forget clients that have stopped asking, so they neither hold memory nor
/// dilute the share of the clients that are still here.
fn prune(table: &mut ClientTable, now: Instant) {
    let over_capacity = table.loads.len() > MAX_TRACKED_CLIENTS;
    if !over_capacity && now.saturating_duration_since(table.pruned_at) < PRUNE_INTERVAL {
        return;
    }
    table.loads.retain(|_, load| {
        load.in_flight.load(Ordering::Acquire) > 0
            || (!over_capacity && now.saturating_duration_since(load.last_seen) < CLIENT_IDLE_AFTER)
    });
    table.pruned_at = now;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DebouncedStatus {
    Unknown,
    Healthy,
    Degraded,
}

/// Why resolution is failing. Both are the same event to the client — it asked
/// and got nothing usable — but they are different things to fix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Failure {
    /// The gateway tried and the upstream did not answer.
    Upstream,
    /// The gateway refused before trying, on admission control.
    Admission,
}

/// A verdict worth publishing, with the cause that produced it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Verdict {
    status: DebouncedStatus,
    cause: Option<Failure>,
}

/// How long a degraded verdict is held before a recovery may clear it.
///
/// The thresholds either side of this are counts of queries, not durations. On
/// a gateway serving ~31 qps, three failures and two successes are about a
/// tenth of a second and a twentieth of a second, so on their own they turn a
/// burst of upstream failures into a state change and back before anything can
/// observe it: a gauge read every 15-60s never samples it, and the bounded
/// transition history fills with pairs that cancel within the same timestamp.
/// A degraded episode has to outlive a scrape interval to be worth publishing
/// at all.
const DEGRADED_DWELL: Duration = Duration::from_secs(60);

/// How often an unchanged verdict is re-published, so the check keeps a recent
/// observation without costing a snapshot clone per query.
const HEALTH_REPUBLISH_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug)]
struct DnsHealthState {
    status: DebouncedStatus,
    consecutive_failures: u32,
    consecutive_successes: u32,
    failure_threshold: u32,
    success_threshold: u32,
    /// Fixed for the length of an episode, so the reason code the check
    /// publishes does not alternate while it stays degraded.
    degraded_cause: Option<Failure>,
    degraded_since: Option<Instant>,
    published_at: Option<Instant>,
}

impl DnsHealthState {
    fn new(failure_threshold: u32, success_threshold: u32) -> Self {
        Self {
            status: DebouncedStatus::Unknown,
            consecutive_failures: 0,
            consecutive_successes: 0,
            failure_threshold,
            success_threshold,
            degraded_cause: None,
            degraded_since: None,
            published_at: None,
        }
    }

    /// Fold one query's outcome into the verdict, returning it when it is worth
    /// publishing. `failure` is `None` for a query that was answered.
    fn record(&mut self, failure: Option<Failure>, now: Instant) -> Option<Verdict> {
        match failure {
            None => {
                self.consecutive_failures = 0;
                self.consecutive_successes = self.consecutive_successes.saturating_add(1);
                match self.status {
                    DebouncedStatus::Unknown => self.enter(DebouncedStatus::Healthy, None, now),
                    DebouncedStatus::Degraded
                        if self.consecutive_successes >= self.success_threshold
                            && self.degraded_for(now) >= DEGRADED_DWELL =>
                    {
                        self.enter(DebouncedStatus::Healthy, None, now)
                    }
                    _ => self.reaffirm(now),
                }
            }
            Some(cause) => {
                self.consecutive_successes = 0;
                self.consecutive_failures = self.consecutive_failures.saturating_add(1);
                match self.status {
                    DebouncedStatus::Unknown | DebouncedStatus::Healthy
                        if self.consecutive_failures >= self.failure_threshold =>
                    {
                        self.enter(DebouncedStatus::Degraded, Some(cause), now)
                    }
                    _ => self.reaffirm(now),
                }
            }
        }
    }

    fn enter(
        &mut self,
        status: DebouncedStatus,
        cause: Option<Failure>,
        now: Instant,
    ) -> Option<Verdict> {
        self.status = status;
        self.degraded_cause = cause;
        self.degraded_since = (status == DebouncedStatus::Degraded).then_some(now);
        self.published_at = Some(now);
        Some(Verdict { status, cause })
    }

    /// Re-state an unchanged verdict, but no more often than the republish
    /// interval: at 31 qps, publishing per query is 31 snapshot clones a second
    /// that say nothing new.
    fn reaffirm(&mut self, now: Instant) -> Option<Verdict> {
        if self.status == DebouncedStatus::Unknown {
            return None;
        }
        match self.published_at {
            Some(at) if now.saturating_duration_since(at) < HEALTH_REPUBLISH_INTERVAL => None,
            _ => {
                self.published_at = Some(now);
                Some(Verdict {
                    status: self.status,
                    cause: self.degraded_cause,
                })
            }
        }
    }

    fn degraded_for(&self, now: Instant) -> Duration {
        self.degraded_since
            .map(|since| now.saturating_duration_since(since))
            .unwrap_or_default()
    }
}

struct ForwardResult {
    response: Vec<u8>,
    tcp_used: bool,
    udp_succeeded: bool,
    failed_udp_attempts: u32,
}

fn record_refusal(refusal: Refusal) {
    match refusal {
        Refusal::GlobalLimit => &QUERIES_REFUSED_GLOBAL,
        Refusal::ClientLimit => &QUERIES_REFUSED_PER_CLIENT,
    }
    .fetch_add(1, Ordering::Relaxed);
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
egressy_dns_upstream_tcp_fallback_successes_total {}\n\
# HELP egressy_dns_local_answers_total Queries answered from enrolled-bridge names without forwarding.\n\
# TYPE egressy_dns_local_answers_total counter\n\
egressy_dns_local_answers_total {}\n\
# HELP egressy_dns_cache_hits_total Queries served from the response cache.\n\
# TYPE egressy_dns_cache_hits_total counter\n\
egressy_dns_cache_hits_total {}\n\
# HELP egressy_dns_cache_misses_total Queries the response cache could not serve.\n\
# TYPE egressy_dns_cache_misses_total counter\n\
egressy_dns_cache_misses_total {}\n\
# HELP egressy_dns_queries_refused_total Queries refused by admission control, by limit.\n\
# TYPE egressy_dns_queries_refused_total counter\n\
egressy_dns_queries_refused_total{{limit=\"global\"}} {}\n\
egressy_dns_queries_refused_total{{limit=\"per_client\"}} {}\n{}",
        UDP_QUERIES.load(Ordering::Relaxed),
        UDP_ATTEMPTS.load(Ordering::Relaxed),
        UDP_TIMEOUTS.load(Ordering::Relaxed),
        UDP_EXHAUSTED.load(Ordering::Relaxed),
        TCP_FALLBACKS.load(Ordering::Relaxed),
        TCP_FALLBACK_SUCCESSES.load(Ordering::Relaxed),
        LOCAL_ANSWERS.load(Ordering::Relaxed),
        CACHE_HITS.load(Ordering::Relaxed),
        CACHE_MISSES.load(Ordering::Relaxed),
        QUERIES_REFUSED_GLOBAL.load(Ordering::Relaxed),
        QUERIES_REFUSED_PER_CLIENT.load(Ordering::Relaxed),
        resolution_health_metric(),
    )
}

/// Emitted only once a debounced verdict exists, so alerts are not armed by a
/// gateway that has simply not resolved anything yet.
fn resolution_health_metric() -> String {
    match RESOLUTION_HEALTHY.load(Ordering::Relaxed) {
        u64::MAX => String::new(),
        value => format!(
            "# HELP egressy_dns_resolution_healthy Debounced in-tunnel resolution health, 1 healthy 0 degraded.\n\
# TYPE egressy_dns_resolution_healthy gauge\n\
egressy_dns_resolution_healthy {value}\n"
        ),
    }
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
    let permits = Arc::new(QueryPermits::new(
        settings.max_concurrent_queries,
        settings.max_concurrent_queries_per_client,
    ));
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
    permits: Arc<QueryPermits>,
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
        if let Some(response) =
            local_answer(&settings, &query).or_else(|| cached_answer(&settings, &query))
        {
            if let Err(error) = listener.send_to(&response, client).await {
                warn!(%client, %error, "DNS answer could not be sent without forwarding");
            }
            continue;
        }
        let listener = Arc::clone(&listener);
        let settings = settings.clone();
        let health = Arc::clone(&health);
        let permit = match permits.try_acquire(client.ip()) {
            Ok(permit) => permit,
            Err(refusal) => {
                record_refusal(refusal);
                warn!(%client, ?refusal, "DNS query refused by concurrency limit");
                // A refused query is a failure to resolve, whoever caused it.
                observe_resolution_health(
                    settings.publisher.as_ref(),
                    &health,
                    Some(Failure::Admission),
                )
                .await;
                // REFUSED, not silence: the gateway declined to try, which is a
                // condition the client can act on now rather than in five
                // seconds' time.
                answer_with_rcode(&listener, client, &query, ResponseCode::Refused).await;
                continue;
            }
        };
        workers.spawn(async move {
            let (_global, client_slot) = permit.into_parts();
            // Given back as soon as the query stops competing for admission,
            // which is when it leaves UDP for the TCP fallback. Beyond that
            // point it is waiting on the upstream, and a query waiting on a
            // slow resolver must not be refusing another client's.
            let mut client_slot = Some(client_slot);
            let Some(upstream) = *settings.upstream.borrow() else {
                observe_resolution_health(
                    settings.publisher.as_ref(),
                    &health,
                    Some(Failure::Upstream),
                )
                .await;
                warn!(%client, "DNS upstream is not configured");
                answer_with_rcode(&listener, client, &query, ResponseCode::ServFail).await;
                return;
            };
            match forward_query(
                &query,
                upstream,
                settings.timeout,
                settings.udp_attempts,
                || {
                    client_slot.take();
                },
            )
            .await
            {
                Ok(result) => {
                    observe_resolution_health(
                        settings.publisher.as_ref(),
                        &health,
                        (!result.udp_succeeded).then_some(Failure::Upstream),
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
                    remember_answer(&settings, &query, &result.response, upstream);
                    if let Err(error) = listener.send_to(&result.response, client).await {
                        warn!(%client, %error, "sending DNS response failed");
                    }
                }
                Err(error) => {
                    observe_resolution_health(
                        settings.publisher.as_ref(),
                        &health,
                        Some(Failure::Upstream),
                    )
                    .await;
                    warn!(%client, %error, "DNS forwarding failed");
                    // SERVFAIL: the gateway tried and could not get an answer.
                    answer_with_rcode(&listener, client, &query, ResponseCode::ServFail).await;
                }
            }
        });
    }
}

async fn serve_tcp(
    listener: TcpListener,
    settings: Settings,
    permits: Arc<QueryPermits>,
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
        let permit = match permits.try_acquire(address.ip()) {
            Ok(permit) => permit,
            Err(refusal) => {
                record_refusal(refusal);
                warn!(%address, ?refusal, "DNS query refused by concurrency limit");
                // Refusing costs a read and a write, not a permit: the point of
                // saying REFUSED is that the client stops waiting, and a client
                // that has already opened a connection is waiting.
                let request_timeout = settings.timeout;
                workers.spawn(async move {
                    if let Err(error) = refuse_tcp_client(&mut client, request_timeout).await {
                        debug!(%address, %error, "refusing a TCP DNS query failed");
                    }
                });
                continue;
            }
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
    if let Some(response) =
        local_answer(settings, &query).or_else(|| cached_answer(settings, &query))
    {
        return write_tcp_message(client, &response, settings.timeout).await;
    }
    match forward_over_tcp(&query, settings).await {
        Ok(response) => write_tcp_message(client, &response, settings.timeout).await,
        Err(error) => {
            // Say SERVFAIL before dropping the connection, so the client fails
            // this query rather than reading the close as a transport problem
            // and retrying the whole exchange.
            if let Some(response) = rcode_response(&query, ResponseCode::ServFail) {
                let _ = write_tcp_message(client, &response, settings.timeout).await;
            }
            Err(error)
        }
    }
}

async fn forward_over_tcp(query: &[u8], settings: &Settings) -> anyhow::Result<Vec<u8>> {
    let upstream = (*settings.upstream.borrow()).context("DNS upstream is not configured")?;
    let response = tcp_exchange(query, upstream, settings.timeout).await?;
    observe_tcp_success(settings.publisher.as_ref()).await;
    remember_answer(settings, query, &response, upstream);
    Ok(response)
}

/// Read a query only far enough to answer it REFUSED.
async fn refuse_tcp_client(
    client: &mut TcpStream,
    request_timeout: Duration,
) -> anyhow::Result<()> {
    let query = read_tcp_message(client, request_timeout).await?;
    let response =
        rcode_response(&query, ResponseCode::Refused).context("query could not be refused")?;
    write_tcp_message(client, &response, request_timeout).await
}

/// Run the retry ladder for one query.
///
/// `leaving_udp` is called when the query gives up on UDP for the TCP fallback,
/// so the caller can release admission capacity it no longer needs to hold. It
/// may be called more than once and must be idempotent.
async fn forward_query(
    query: &[u8],
    upstream: SocketAddr,
    request_timeout: Duration,
    udp_attempts: u32,
    mut leaving_udp: impl FnMut(),
) -> anyhow::Result<ForwardResult> {
    validate_dns_message(query)?;
    let mut last_error = None;
    let mut failed_udp_attempts = 0;
    for attempt in 1..=udp_attempts {
        UDP_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
        match udp_exchange(query, upstream, request_timeout).await {
            Ok(response) if is_truncated(&response)? => {
                debug!("DNS UDP response truncated; retrying over TCP");
                leaving_udp();
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
    leaving_udp();
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

/// Fold one query's outcome into the published resolution verdict.
///
/// Every outcome a client experiences belongs here, not just the ones that
/// reached the upstream. A query refused by admission control never reached a
/// worker, so the check could not see the largest failure population on the
/// reported gateway by construction — 14,343 refusals against 229 forwarding
/// failures — and reported healthy throughout while a client had no working
/// DNS at all.
async fn observe_resolution_health(
    publisher: Option<&StatePublisher>,
    health: &Mutex<DnsHealthState>,
    failure: Option<Failure>,
) {
    let Some(publisher) = publisher else { return };
    let observation = health.lock().await.record(failure, Instant::now());
    let Some(verdict) = observation else { return };
    let healthy = verdict.status == DebouncedStatus::Healthy;
    RESOLUTION_HEALTHY.store(u64::from(healthy), Ordering::Relaxed);
    let (reason_code, message) = match verdict.cause {
        None => (
            "dns.udp_healthy",
            "The in-tunnel resolver answered over UDP",
        ),
        Some(Failure::Upstream) => (
            "dns.upstream_udp_failures",
            "Consecutive queries exhausted all in-tunnel UDP attempts",
        ),
        Some(Failure::Admission) => (
            "dns.queries_refused",
            "Consecutive queries were refused before reaching the resolver",
        ),
    };
    publisher
        .observe(
            "dns.upstream_udp",
            if healthy {
                CheckStatus::Healthy
            } else {
                CheckStatus::Degraded
            },
            Impact::Critical,
            reason_code,
            message,
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

/// A response carrying nothing but an rcode, echoing the question asked.
///
/// Silence is the one answer a resolver client cannot act on: it cannot tell a
/// refusal from a gateway that has gone away, so it waits out its own timeout
/// — 5s with two attempts per nameserver on glibc — and retries. Under load
/// those retries arrive as a second wave against the capacity that refused the
/// first, which is how an upstream hiccup became sustained refusal. An rcode
/// fails the client immediately and lets it apply its own backoff.
///
/// `None` for anything unparseable: there is no question to echo and no
/// transaction to answer, so there is nothing truthful to send.
fn rcode_response(query: &[u8], code: ResponseCode) -> Option<Vec<u8>> {
    let request = Message::from_vec(query).ok()?;
    if request.metadata.message_type != MessageType::Query {
        return None;
    }
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.metadata.response_code = code;
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.queries = request.queries.clone();
    // RFC 6891: a responder that was sent an OPT record includes one in reply.
    if let Some(edns) = request.edns.clone() {
        response.set_edns(edns);
    }
    response.to_vec().ok()
}

/// Answer a UDP query with an rcode, or say why it could not be answered.
async fn answer_with_rcode(
    listener: &UdpSocket,
    client: SocketAddr,
    query: &[u8],
    code: ResponseCode,
) {
    let Some(response) = rcode_response(query, code) else {
        debug!(%client, ?code, "DNS query could not be answered with an rcode");
        return;
    };
    if let Err(error) = listener.send_to(&response, client).await {
        warn!(%client, %error, ?code, "sending DNS rcode response failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolution_health_is_absent_until_a_verdict_exists() {
        // A gateway that has not resolved anything yet must not arm an alert.
        RESOLUTION_HEALTHY.store(u64::MAX, Ordering::Relaxed);
        assert!(resolution_health_metric().is_empty());
    }

    #[test]
    fn resolution_health_reports_both_verdicts() {
        RESOLUTION_HEALTHY.store(1, Ordering::Relaxed);
        assert!(resolution_health_metric().contains("egressy_dns_resolution_healthy 1"));
        RESOLUTION_HEALTHY.store(0, Ordering::Relaxed);
        assert!(resolution_health_metric().contains("egressy_dns_resolution_healthy 0"));
        RESOLUTION_HEALTHY.store(u64::MAX, Ordering::Relaxed);
    }

    fn client(last: u8) -> IpAddr {
        IpAddr::from([172, 30, 0, last])
    }

    #[test]
    fn one_client_cannot_consume_the_whole_global_budget() {
        // The observed incident: a single client bursting hard enough to
        // starve every other enrolled client.
        let permits = QueryPermits::new(8, Some(2));
        let _held: Vec<_> = (0..2)
            .map(|_| {
                permits
                    .try_acquire(client(11))
                    .expect("within client share")
            })
            .collect();
        assert_eq!(
            permits.try_acquire(client(11)).unwrap_err(),
            Refusal::ClientLimit
        );
        // A different client is unaffected.
        assert!(permits.try_acquire(client(12)).is_ok());
    }

    #[test]
    fn the_global_limit_still_applies_across_clients() {
        let permits = QueryPermits::new(2, Some(2));
        let _a = permits.try_acquire(client(11)).unwrap();
        let _b = permits.try_acquire(client(12)).unwrap();
        assert_eq!(
            permits.try_acquire(client(13)).unwrap_err(),
            Refusal::GlobalLimit
        );
    }

    #[test]
    fn permits_are_returned_when_a_query_finishes() {
        let permits = QueryPermits::new(4, Some(1));
        {
            let _held = permits.try_acquire(client(11)).unwrap();
            assert!(permits.try_acquire(client(11)).is_err());
        }
        assert!(permits.try_acquire(client(11)).is_ok());
    }

    #[test]
    fn a_single_client_may_use_the_whole_global_budget() {
        // The observed failure: 14,237 queries refused on the per-client bound
        // while the global budget was never once reached, on a bridge with
        // effectively one DNS client. A share of one is the whole thing.
        let permits = QueryPermits::new(512, None);
        let held: Vec<_> = (0..512)
            .map(|_| permits.try_acquire(client(11)).expect("within the budget"))
            .collect();
        // The whole configured capacity, not the eighth of it a fixed 64 left
        // reachable while 448 permits sat idle.
        assert_eq!(held.len(), permits.global_limit);
        assert!(permits.try_acquire(client(11)).is_err());
        drop(held);
    }

    #[test]
    fn the_share_narrows_as_clients_arrive_and_never_below_the_floor() {
        let permits = QueryPermits::new(512, None);
        assert_eq!(permits.limit_for(1), 512);
        assert_eq!(permits.limit_for(2), 256);
        assert_eq!(permits.limit_for(8), 64);
        // Past the floor the global budget is the bound that should shed load;
        // squeezing every client further only refuses traffic the gateway has
        // the capacity to serve.
        assert_eq!(permits.limit_for(64), MIN_CLIENT_SHARE);
        assert_eq!(permits.limit_for(4096), MIN_CLIENT_SHARE);
    }

    #[test]
    fn the_share_reflects_the_clients_actually_using_the_forwarder() {
        let permits = QueryPermits::new(512, None);
        let _first = permits.try_acquire(client(11)).unwrap();
        assert_eq!(permits.tracked_clients(), 1);
        let _second = permits.try_acquire(client(12)).unwrap();
        assert_eq!(permits.tracked_clients(), 2);
    }

    #[test]
    fn idle_capacity_is_lent_to_a_client_past_its_share() {
        // The residual after #21: one busy client refused against a share of
        // 64-102 while all 512 permits sat free. Nobody was being starved,
        // because nobody else wanted any of it.
        let permits = crowded_permits();
        let held: Vec<_> = (0..128)
            .map(|_| {
                permits
                    .try_acquire(client(11))
                    .expect("idle capacity is lent out")
            })
            .collect();
        assert!(held.len() > permits.limit_for(permits.tracked_clients()));
    }

    /// Eight clients present, so the derived share is 64 of the 512 budget.
    fn crowded_permits() -> QueryPermits {
        let permits = QueryPermits::new(512, None);
        for last in 11..19 {
            drop(permits.try_acquire(client(last)));
        }
        assert_eq!(permits.limit_for(permits.tracked_clients()), 64);
        permits
    }

    #[test]
    fn a_burst_stops_at_the_reserve_and_the_share_binds_again() {
        // Borrowing is not unlimited: once the free pool reaches the reserve,
        // a client already holding more than its share is refused.
        let permits = crowded_permits();
        let mut held = Vec::new();
        while let Ok(permit) = permits.try_acquire(client(11)) {
            held.push(permit);
            assert!(held.len() <= 512, "borrowing never stopped");
        }
        assert!(held.len() > 64, "the share should have been lent past");
        assert!(
            permits.global.available_permits() >= permits.borrow_reserve,
            "the reserve was consumed"
        );
    }

    #[test]
    fn the_reserve_keeps_a_quiet_client_admissible() {
        // What the reserve is for: a burst from one client must not leave a
        // client that has asked for nothing with nowhere to go.
        let permits = crowded_permits();
        let mut held = Vec::new();
        while let Ok(permit) = permits.try_acquire(client(11)) {
            held.push(permit);
            if held.len() > 512 {
                break;
            }
        }
        assert!(
            permits.try_acquire(client(12)).is_ok(),
            "a quiet client was starved by a burst"
        );
    }

    #[test]
    fn a_fixed_ceiling_is_never_borrowed_past() {
        // An operator who names a number gets that number, idle budget or not.
        let permits = QueryPermits::new(512, Some(4));
        let _held: Vec<_> = (0..4)
            .map(|_| permits.try_acquire(client(11)).expect("within the ceiling"))
            .collect();
        assert!(permits.global.available_permits() > permits.borrow_reserve);
        assert_eq!(
            permits.try_acquire(client(11)).unwrap_err(),
            Refusal::ClientLimit
        );
    }

    #[test]
    fn a_fixed_ceiling_overrides_the_derived_share() {
        // An operator who sets the key gets exactly what they asked for, on a
        // gateway of any size.
        let permits = QueryPermits::new(512, Some(4));
        let _held: Vec<_> = (0..4)
            .map(|_| permits.try_acquire(client(11)).expect("within the ceiling"))
            .collect();
        assert_eq!(
            permits.try_acquire(client(11)).unwrap_err(),
            Refusal::ClientLimit
        );
    }

    #[test]
    fn a_query_that_leaves_udp_stops_holding_admission() {
        // Upstream latency must degrade latency, not close the door: the slot
        // goes back when the query stops competing for admission, while the
        // global permit keeps bounding the work itself.
        let permits = QueryPermits::new(4, Some(1));
        let (global, slot) = permits.try_acquire(client(11)).unwrap().into_parts();
        assert_eq!(
            permits.try_acquire(client(11)).unwrap_err(),
            Refusal::ClientLimit
        );
        drop(slot);
        let next = permits.try_acquire(client(11));
        assert!(next.is_ok(), "the share should be free once released");
        drop(global);
    }

    #[test]
    fn a_per_client_limit_above_the_global_one_is_clamped() {
        let permits = QueryPermits::new(2, Some(99));
        assert_eq!(permits.limit_for(1), 2);
        let _a = permits.try_acquire(client(11)).unwrap();
        let _b = permits.try_acquire(client(11)).unwrap();
        // Refused either way; a client share declared wider than the global
        // budget must never let one client exceed the global bound.
        assert!(permits.try_acquire(client(11)).is_err());
    }

    #[test]
    fn idle_client_entries_do_not_accumulate_without_bound() {
        let permits = QueryPermits::new(4096, Some(2));
        for index in 0..(MAX_TRACKED_CLIENTS + 64) {
            let address = IpAddr::from(((index as u32) + 1).to_be_bytes());
            drop(permits.try_acquire(address));
        }
        let tracked = permits.clients.lock().unwrap().loads.len();
        assert!(tracked <= MAX_TRACKED_CLIENTS + 1, "tracked {tracked}");
    }

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

    use hickory_proto::{
        op::{OpCode, Query},
        rr::{Name, RecordType},
    };

    fn dns_query(name: &str) -> Vec<u8> {
        let mut message = Message::new(4242, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
        message.to_vec().unwrap()
    }

    #[test]
    fn an_rcode_response_answers_the_question_it_was_asked() {
        let query = dns_query("a.test.");
        let bytes = rcode_response(&query, ResponseCode::Refused).unwrap();
        let response = Message::from_vec(&bytes).unwrap();
        assert_eq!(response.metadata.id, 4242);
        assert_eq!(response.metadata.message_type, MessageType::Response);
        assert_eq!(response.metadata.response_code, ResponseCode::Refused);
        assert!(response.metadata.recursion_desired);
        assert!(response.metadata.recursion_available);
        assert_eq!(response.queries.len(), 1);
        assert_eq!(response.queries[0].name().to_ascii(), "a.test.");
        // Validation the forwarder applies to upstream responses holds here
        // too: same transaction, response bit set.
        validate_response(&query, &bytes).unwrap();
    }

    #[test]
    fn both_failure_rcodes_are_distinguishable_to_the_client() {
        let query = dns_query("a.test.");
        let refused = Message::from_vec(&rcode_response(&query, ResponseCode::Refused).unwrap())
            .unwrap()
            .metadata
            .response_code;
        let failed = Message::from_vec(&rcode_response(&query, ResponseCode::ServFail).unwrap())
            .unwrap()
            .metadata
            .response_code;
        // "I declined to try" and "I tried and could not" are different
        // conditions and the client backs off differently for each.
        assert_eq!(refused, ResponseCode::Refused);
        assert_eq!(failed, ResponseCode::ServFail);
    }

    #[test]
    fn nothing_is_sent_for_a_message_that_cannot_be_answered() {
        // No question to echo and no transaction to answer.
        assert!(rcode_response(b"nonsense", ResponseCode::ServFail).is_none());
        let mut response = Message::response(1, OpCode::Query);
        response.add_query(Query::query(
            Name::from_ascii("a.test.").unwrap(),
            RecordType::A,
        ));
        assert!(rcode_response(&response.to_vec().unwrap(), ResponseCode::ServFail).is_none());
    }

    #[tokio::test]
    async fn a_refused_query_is_answered_rather_than_dropped() {
        // The regression that mattered: a client that gets silence waits out
        // its own resolver timeout and retries into the capacity that just
        // refused it.
        let gateway = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let query = dns_query("a.test.");
        answer_with_rcode(
            &gateway,
            client.local_addr().unwrap(),
            &query,
            ResponseCode::Refused,
        )
        .await;
        let mut buffer = vec![0_u8; MAX_DNS_MESSAGE];
        let length = timeout(Duration::from_secs(5), client.recv(&mut buffer))
            .await
            .expect("the gateway answered")
            .unwrap();
        buffer.truncate(length);
        let response = Message::from_vec(&buffer).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::Refused);
        assert_eq!(response.metadata.id, 4242);
    }

    fn status_of(verdict: Option<Verdict>) -> Option<DebouncedStatus> {
        verdict.map(|verdict| verdict.status)
    }

    #[test]
    fn dns_health_requires_consecutive_failures_before_degrading() {
        let mut health = DnsHealthState::new(3, 2);
        let start = Instant::now();
        assert_eq!(
            status_of(health.record(None, start)),
            Some(DebouncedStatus::Healthy)
        );
        // An isolated failure is noise; the counters exist to ignore it.
        assert_eq!(health.record(Some(Failure::Upstream), start), None);
        assert_eq!(health.record(None, start), None);
        assert_eq!(health.record(Some(Failure::Upstream), start), None);
        assert_eq!(health.record(Some(Failure::Upstream), start), None);
        assert_eq!(
            status_of(health.record(Some(Failure::Upstream), start)),
            Some(DebouncedStatus::Degraded)
        );
    }

    #[test]
    fn a_degraded_verdict_outlives_the_burst_that_caused_it() {
        // The observed failure: 23 degraded episodes, every one of them back to
        // healthy within the same second and 15 within the same timestamp. A
        // gauge scraped every 15-60s never sampled one, so a resolver in
        // trouble published healthy throughout.
        let mut health = DnsHealthState::new(3, 2);
        let start = Instant::now();
        for _ in 0..3 {
            health.record(Some(Failure::Upstream), start);
        }
        assert_eq!(health.status, DebouncedStatus::Degraded);

        // Two successes 65ms later would have cleared it before.
        let burst_over = start + Duration::from_millis(65);
        assert_eq!(health.record(None, burst_over), None);
        assert_eq!(health.record(None, burst_over), None);
        assert_eq!(health.status, DebouncedStatus::Degraded);

        // Held until the episode has lasted long enough to be observable, then
        // cleared by the successes that were already accumulating.
        let settled = start + DEGRADED_DWELL;
        assert_eq!(
            status_of(health.record(None, settled)),
            Some(DebouncedStatus::Healthy)
        );
    }

    #[test]
    fn refusals_degrade_resolution_health_on_their_own() {
        // A client whose queries are all being refused has no working DNS,
        // whatever the upstream would have said.
        let mut health = DnsHealthState::new(3, 2);
        let start = Instant::now();
        health.record(None, start);
        for _ in 0..2 {
            assert_eq!(health.record(Some(Failure::Admission), start), None);
        }
        let verdict = health.record(Some(Failure::Admission), start).unwrap();
        assert_eq!(verdict.status, DebouncedStatus::Degraded);
        assert_eq!(verdict.cause, Some(Failure::Admission));
    }

    #[test]
    fn the_cause_stays_fixed_for_the_length_of_an_episode() {
        // Otherwise an episode with both causes churns the bounded transition
        // history with reason-code changes that are not state changes.
        let mut health = DnsHealthState::new(1, 1);
        let start = Instant::now();
        let verdict = health.record(Some(Failure::Admission), start).unwrap();
        assert_eq!(verdict.cause, Some(Failure::Admission));
        let later = start + HEALTH_REPUBLISH_INTERVAL;
        let reaffirmed = health.record(Some(Failure::Upstream), later).unwrap();
        assert_eq!(reaffirmed.status, DebouncedStatus::Degraded);
        assert_eq!(reaffirmed.cause, Some(Failure::Admission));
    }

    #[test]
    fn an_unchanged_verdict_is_not_republished_per_query() {
        // At ~31 qps this was a snapshot clone and a broadcast per query, all
        // of them saying the same thing.
        let mut health = DnsHealthState::new(3, 2);
        let start = Instant::now();
        assert!(health.record(None, start).is_some());
        assert_eq!(health.record(None, start + Duration::from_secs(1)), None);
        assert!(health
            .record(None, start + HEALTH_REPUBLISH_INTERVAL)
            .is_some());
    }
}
