//! A bounded response cache for the forwarder.
//!
//! Every query previously cost a full round trip through the tunnel and one
//! admission-control permit, however often the same name was asked for. That is
//! most of the traffic on a gateway serving torrent clients and indexers, and it
//! is what let a single client saturate the forwarder while recovering from an
//! outage.
//!
//! Entries expire on the shortest TTL in the answer, so this never serves a
//! record for longer than its authority allows, and remaining TTLs are counted
//! down on the way out so clients see a consistent view.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

use hickory_proto::{
    op::{Message, MessageType, ResponseCode},
    rr::{DNSClass, RecordType},
};

/// Upper bound on how long an entry may be served, whatever the record says.
/// Provider resolvers occasionally hand out very long TTLs, and a gateway that
/// pins those across a tunnel change would serve stale answers.
pub const MAX_TTL: Duration = Duration::from_secs(300);

/// Below this there is no point caching; the entry would expire before reuse.
pub const MIN_TTL: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Key {
    /// The resolver the answer came from. Answers are frequently
    /// resolver-dependent, and a tunnel that changes exit server must not serve
    /// what the previous one said. Keying on it makes that a miss rather than
    /// requiring a flush, with no window in between.
    upstream: SocketAddr,
    name: String,
    record_type: RecordType,
    dns_class: DNSClass,
}

#[derive(Clone, Debug)]
struct Entry {
    response: Message,
    stored_at: Instant,
    ttl: Duration,
}

/// Bounded, TTL-respecting cache of upstream responses.
#[derive(Debug)]
pub struct DnsCache {
    entries: Mutex<HashMap<Key, Entry>>,
    capacity: usize,
}

impl DnsCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            capacity: capacity.max(1),
        }
    }

    /// A cached response for this query, with TTLs counted down and the
    /// transaction ID rewritten to match the caller.
    pub fn lookup(&self, query: &[u8], upstream: SocketAddr, now: Instant) -> Option<Vec<u8>> {
        let request = Message::from_vec(query).ok()?;
        let key = key_for(&request, upstream)?;
        let mut entries = self.lock();
        let entry = entries.get(&key)?;
        let elapsed = now.saturating_duration_since(entry.stored_at);
        if elapsed >= entry.ttl {
            entries.remove(&key);
            return None;
        }
        let remaining = (entry.ttl - elapsed).as_secs() as u32;
        let mut response = entry.response.clone();
        drop(entries);

        response.metadata.id = request.metadata.id;
        response.metadata.recursion_desired = request.metadata.recursion_desired;
        response.queries = request.queries.clone();
        for record in response.answers.iter_mut() {
            record.ttl = remaining;
        }
        response.to_vec().ok()
    }

    /// Remember a successful upstream response.
    ///
    /// Only cacheable answers are kept: a complete `NOERROR` reply to a single
    /// question, carrying at least one record with a usable TTL. Truncated,
    /// error and empty responses are left alone rather than guessed at.
    pub fn store(&self, query: &[u8], response: &[u8], upstream: SocketAddr, now: Instant) {
        let Ok(request) = Message::from_vec(query) else {
            return;
        };
        let Ok(parsed) = Message::from_vec(response) else {
            return;
        };
        let Some(key) = key_for(&request, upstream) else {
            return;
        };
        let Some(ttl) = cacheable_ttl(&parsed) else {
            return;
        };
        let mut entries = self.lock();
        if entries.len() >= self.capacity && !entries.contains_key(&key) {
            evict_one(&mut entries, now);
        }
        entries.insert(
            key,
            Entry {
                response: parsed,
                stored_at: now,
                ttl,
            },
        );
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.lock().len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Key, Entry>> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// The cache key, or `None` for anything not safely cacheable by question.
fn key_for(request: &Message, upstream: SocketAddr) -> Option<Key> {
    if request.queries.len() != 1 {
        return None;
    }
    let question = request.queries.first()?;
    Some(Key {
        upstream,
        name: question.name().to_ascii().to_ascii_lowercase(),
        record_type: question.query_type(),
        dns_class: question.query_class(),
    })
}

/// How long this response may be served, or `None` if it must not be cached.
fn cacheable_ttl(response: &Message) -> Option<Duration> {
    if response.metadata.message_type != MessageType::Response
        || response.metadata.response_code != ResponseCode::NoError
        || response.metadata.truncation
        || response.answers.is_empty()
    {
        return None;
    }
    let smallest = response.answers.iter().map(|record| record.ttl).min()?;
    let ttl = Duration::from_secs(u64::from(smallest)).min(MAX_TTL);
    (ttl >= MIN_TTL).then_some(ttl)
}

/// Drop an expired entry if there is one, otherwise the oldest.
///
/// Cheap and adequate at this size; the cache exists to absorb bursts of
/// repeated names, not to be a general-purpose LRU.
fn evict_one(entries: &mut HashMap<Key, Entry>, now: Instant) {
    let expired = entries
        .iter()
        .find(|(_, entry)| now.saturating_duration_since(entry.stored_at) >= entry.ttl)
        .map(|(key, _)| key.clone());
    let victim = expired.or_else(|| {
        entries
            .iter()
            .min_by_key(|(_, entry)| entry.stored_at)
            .map(|(key, _)| key.clone())
    });
    if let Some(key) = victim {
        entries.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{
        op::{OpCode, Query},
        rr::{rdata::A, Name, RData, Record},
    };
    use std::net::{Ipv4Addr, SocketAddr};

    fn upstream() -> SocketAddr {
        "10.2.0.1:53".parse().unwrap()
    }

    fn other_upstream() -> SocketAddr {
        "10.9.0.1:53".parse().unwrap()
    }

    fn query(name: &str) -> Vec<u8> {
        let mut message = Message::new(7, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
        message.to_vec().unwrap()
    }

    fn response(name: &str, ttl: u32, address: [u8; 4]) -> Vec<u8> {
        let mut message = Message::response(7, OpCode::Query);
        message.metadata.response_code = ResponseCode::NoError;
        message.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
        message.add_answer(Record::from_rdata(
            Name::from_ascii(name).unwrap(),
            ttl,
            RData::A(A(Ipv4Addr::from(address))),
        ));
        message.to_vec().unwrap()
    }

    fn empty_response(name: &str, code: ResponseCode) -> Vec<u8> {
        let mut message = Message::response(7, OpCode::Query);
        message.metadata.response_code = code;
        message.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
        message.to_vec().unwrap()
    }

    #[test]
    fn a_stored_response_is_served_again() {
        let cache = DnsCache::new(16);
        let now = Instant::now();
        cache.store(
            &query("a.test."),
            &response("a.test.", 60, [1, 2, 3, 4]),
            upstream(),
            now,
        );
        let hit = cache.lookup(&query("a.test."), upstream(), now).unwrap();
        let message = Message::from_vec(&hit).unwrap();
        assert_eq!(message.answers.len(), 1);
        match &message.answers[0].data {
            RData::A(A(address)) => assert_eq!(*address, Ipv4Addr::new(1, 2, 3, 4)),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn the_transaction_id_is_rewritten_for_the_new_caller() {
        let cache = DnsCache::new(16);
        let now = Instant::now();
        cache.store(
            &query("a.test."),
            &response("a.test.", 60, [1, 2, 3, 4]),
            upstream(),
            now,
        );
        let mut second = Message::new(9999, MessageType::Query, OpCode::Query);
        second.add_query(Query::query(
            Name::from_ascii("a.test.").unwrap(),
            RecordType::A,
        ));
        let hit = cache
            .lookup(&second.to_vec().unwrap(), upstream(), now)
            .unwrap();
        assert_eq!(Message::from_vec(&hit).unwrap().metadata.id, 9999);
    }

    #[test]
    fn remaining_ttl_counts_down_while_cached() {
        let cache = DnsCache::new(16);
        let now = Instant::now();
        cache.store(
            &query("a.test."),
            &response("a.test.", 60, [1, 2, 3, 4]),
            upstream(),
            now,
        );
        let later = now + Duration::from_secs(20);
        let hit = cache.lookup(&query("a.test."), upstream(), later).unwrap();
        assert_eq!(Message::from_vec(&hit).unwrap().answers[0].ttl, 40);
    }

    #[test]
    fn an_expired_entry_is_a_miss_and_is_dropped() {
        let cache = DnsCache::new(16);
        let now = Instant::now();
        cache.store(
            &query("a.test."),
            &response("a.test.", 5, [1, 2, 3, 4]),
            upstream(),
            now,
        );
        assert!(cache
            .lookup(&query("a.test."), upstream(), now + Duration::from_secs(5))
            .is_none());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn a_long_upstream_ttl_is_capped() {
        let cache = DnsCache::new(16);
        let now = Instant::now();
        cache.store(
            &query("a.test."),
            &response("a.test.", 86_400, [1, 2, 3, 4]),
            upstream(),
            now,
        );
        let hit = cache
            .lookup(
                &query("a.test."),
                upstream(),
                now + MAX_TTL - Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(Message::from_vec(&hit).unwrap().answers[0].ttl, 1);
        assert!(cache
            .lookup(&query("a.test."), upstream(), now + MAX_TTL)
            .is_none());
    }

    #[test]
    fn a_different_name_is_not_served_from_another_entry() {
        let cache = DnsCache::new(16);
        let now = Instant::now();
        cache.store(
            &query("a.test."),
            &response("a.test.", 60, [1, 2, 3, 4]),
            upstream(),
            now,
        );
        assert!(cache.lookup(&query("b.test."), upstream(), now).is_none());
    }

    #[test]
    fn errors_truncation_and_empty_answers_are_not_cached() {
        let cache = DnsCache::new(16);
        let now = Instant::now();
        cache.store(
            &query("a.test."),
            &empty_response("a.test.", ResponseCode::NXDomain),
            upstream(),
            now,
        );
        cache.store(
            &query("b.test."),
            &empty_response("b.test.", ResponseCode::NoError),
            upstream(),
            now,
        );
        let mut truncated = Message::from_vec(&response("c.test.", 60, [1, 2, 3, 4])).unwrap();
        truncated.metadata.truncation = true;
        cache.store(
            &query("c.test."),
            &truncated.to_vec().unwrap(),
            upstream(),
            now,
        );
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn a_zero_ttl_answer_is_not_cached() {
        let cache = DnsCache::new(16);
        let now = Instant::now();
        cache.store(
            &query("a.test."),
            &response("a.test.", 0, [1, 2, 3, 4]),
            upstream(),
            now,
        );
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn the_cache_stays_within_its_capacity() {
        let cache = DnsCache::new(4);
        let mut now = Instant::now();
        for index in 0..32 {
            let name = format!("host{index}.test.");
            cache.store(
                &query(&name),
                &response(&name, 60, [10, 0, 0, 1]),
                upstream(),
                now,
            );
            now += Duration::from_millis(1);
        }
        assert!(cache.len() <= 4, "cache held {}", cache.len());
    }

    #[test]
    fn multi_question_queries_are_neither_stored_nor_served() {
        let cache = DnsCache::new(16);
        let now = Instant::now();
        let mut message = Message::new(1, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(
            Name::from_ascii("a.test.").unwrap(),
            RecordType::A,
        ));
        message.add_query(Query::query(
            Name::from_ascii("b.test.").unwrap(),
            RecordType::A,
        ));
        let bytes = message.to_vec().unwrap();
        cache.store(
            &bytes,
            &response("a.test.", 60, [1, 2, 3, 4]),
            upstream(),
            now,
        );
        assert_eq!(cache.len(), 0);
        assert!(cache.lookup(&bytes, upstream(), now).is_none());
    }

    #[test]
    fn malformed_input_is_ignored() {
        let cache = DnsCache::new(16);
        let now = Instant::now();
        cache.store(b"nonsense", b"also nonsense", upstream(), now);
        assert_eq!(cache.len(), 0);
        assert!(cache.lookup(b"nonsense", upstream(), now).is_none());
    }

    #[test]
    fn a_changed_exit_resolver_does_not_serve_the_previous_one_s_answers() {
        // Answers are frequently resolver-dependent, so a tunnel that moves to
        // a different exit must not keep serving what the old one said.
        let cache = DnsCache::new(16);
        let now = Instant::now();
        cache.store(
            &query("a.test."),
            &response("a.test.", 60, [1, 2, 3, 4]),
            upstream(),
            now,
        );
        assert!(cache
            .lookup(&query("a.test."), other_upstream(), now)
            .is_none());
        assert!(cache.lookup(&query("a.test."), upstream(), now).is_some());
    }

    #[test]
    fn record_type_is_part_of_the_key() {
        let cache = DnsCache::new(16);
        let now = Instant::now();
        cache.store(
            &query("a.test."),
            &response("a.test.", 60, [1, 2, 3, 4]),
            upstream(),
            now,
        );
        let mut aaaa = Message::new(3, MessageType::Query, OpCode::Query);
        aaaa.add_query(Query::query(
            Name::from_ascii("a.test.").unwrap(),
            RecordType::AAAA,
        ));
        assert!(cache
            .lookup(&aaaa.to_vec().unwrap(), upstream(), now)
            .is_none());
    }
}
