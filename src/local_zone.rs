//! Answering enrolled-bridge container names locally.
//!
//! Enrolled clients are given the gateway as their only resolver, and the
//! gateway forwards everything to the provider resolver through the tunnel.
//! That makes Egressy unusable for any stack whose containers address each
//! other by Docker service name: the provider has never heard of `qbit-proxy`.
//!
//! This answers those names from the discovery data the gateway already holds,
//! and — just as importantly — stops them being forwarded, so nothing about
//! internal topology reaches the provider resolver.
//!
//! Matching is deliberately restricted to **single-label** names. A container
//! called `api` can therefore never shadow `api.example.com`, and answers are
//! only ever addresses on the enrolled bridge, which keeps this rebinding-safe.

use std::{collections::BTreeMap, net::Ipv4Addr};

use hickory_proto::{
    op::{Message, MessageType, ResponseCode},
    rr::{rdata::A, RData, Record, RecordType},
};

/// Short TTL: these names track container lifecycle, which changes freely.
pub const LOCAL_TTL_SECONDS: u32 = 30;

/// Build a response for a query naming a container on the enrolled bridge.
///
/// Returns `None` when the query is not ours to answer, in which case the
/// caller forwards it upstream exactly as before.
pub fn answer(query: &[u8], names: &BTreeMap<String, Ipv4Addr>) -> Option<Vec<u8>> {
    if names.is_empty() {
        return None;
    }
    let request = Message::from_vec(query).ok()?;
    if request.metadata.message_type != MessageType::Query || request.queries.len() != 1 {
        return None;
    }
    let question = request.queries.first()?;
    let label = single_label(&question.name().to_ascii())?;
    let address = names.get(&label)?;

    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.metadata.authoritative = true;
    response.metadata.response_code = ResponseCode::NoError;
    response.add_query(question.clone());

    // Only A carries an answer. Every other type for a name we own is answered
    // NOERROR with no records rather than forwarded: the name exists, it simply
    // has nothing of that type, and forwarding it would leak the name upstream.
    if question.query_type() == RecordType::A {
        response.add_answer(Record::from_rdata(
            question.name().clone(),
            LOCAL_TTL_SECONDS,
            RData::A(A(*address)),
        ));
    }

    response.to_vec().ok()
}

/// The name as a single lowercase label, or `None` if it is not single-label.
fn single_label(name: &str) -> Option<String> {
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    if trimmed.is_empty() || trimmed.contains('.') {
        return None;
    }
    Some(trimmed.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{
        op::{OpCode, Query},
        rr::Name,
    };

    fn names() -> BTreeMap<String, Ipv4Addr> {
        BTreeMap::from([
            ("qbit-proxy".to_owned(), Ipv4Addr::new(172, 30, 0, 8)),
            ("rustnzb".to_owned(), Ipv4Addr::new(172, 30, 0, 9)),
        ])
    }

    fn query_bytes(name: &str, record_type: RecordType) -> Vec<u8> {
        let mut message = Message::new(4242, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(Name::from_ascii(name).unwrap(), record_type));
        message.to_vec().unwrap()
    }

    fn parse(bytes: &[u8]) -> Message {
        Message::from_vec(bytes).unwrap()
    }

    #[test]
    fn a_container_name_is_answered_with_its_bridge_address() {
        let response = answer(&query_bytes("qbit-proxy.", RecordType::A), &names()).unwrap();
        let message = parse(&response);
        assert_eq!(message.metadata.id, 4242);
        assert_eq!(message.metadata.message_type, MessageType::Response);
        assert_eq!(message.metadata.response_code, ResponseCode::NoError);
        assert_eq!(message.answers.len(), 1);
        match &message.answers[0].data {
            RData::A(A(address)) => assert_eq!(*address, Ipv4Addr::new(172, 30, 0, 8)),
            other => panic!("unexpected record {other:?}"),
        }
    }

    #[test]
    fn the_question_is_echoed_so_clients_accept_the_response() {
        let response = answer(&query_bytes("rustnzb.", RecordType::A), &names()).unwrap();
        let message = parse(&response);
        assert_eq!(message.queries.len(), 1);
        assert_eq!(message.queries[0].name().to_ascii(), "rustnzb.");
    }

    #[test]
    fn an_unknown_name_is_left_to_the_upstream_resolver() {
        assert!(answer(&query_bytes("not-a-container.", RecordType::A), &names()).is_none());
    }

    #[test]
    fn a_public_name_sharing_our_first_label_is_never_shadowed() {
        // Single-label matching is what makes this safe: a container called
        // `rustnzb` must not capture `rustnzb.example.com`.
        assert!(answer(
            &query_bytes("qbit-proxy.example.com.", RecordType::A),
            &names()
        )
        .is_none());
        assert!(answer(
            &query_bytes("rustnzb.internal.test.", RecordType::A),
            &names()
        )
        .is_none());
    }

    #[test]
    fn aaaa_for_a_known_name_is_answered_empty_rather_than_forwarded() {
        // Answering NOERROR with no records keeps the internal name off the
        // wire. Forwarding it would tell the provider resolver it exists.
        let response = answer(&query_bytes("qbit-proxy.", RecordType::AAAA), &names()).unwrap();
        let message = parse(&response);
        assert_eq!(message.metadata.response_code, ResponseCode::NoError);
        assert!(message.answers.is_empty());
    }

    #[test]
    fn other_record_types_for_a_known_name_are_also_kept_internal() {
        let response = answer(&query_bytes("qbit-proxy.", RecordType::TXT), &names()).unwrap();
        assert!(parse(&response).answers.is_empty());
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert!(answer(&query_bytes("QBIT-Proxy.", RecordType::A), &names()).is_some());
    }

    #[test]
    fn an_empty_name_map_answers_nothing() {
        assert!(answer(&query_bytes("qbit-proxy.", RecordType::A), &BTreeMap::new()).is_none());
    }

    #[test]
    fn malformed_and_multi_question_queries_are_forwarded_untouched() {
        assert!(answer(b"not a dns message", &names()).is_none());
        let mut message = Message::new(1, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(
            Name::from_ascii("qbit-proxy.").unwrap(),
            RecordType::A,
        ));
        message.add_query(Query::query(
            Name::from_ascii("rustnzb.").unwrap(),
            RecordType::A,
        ));
        assert!(answer(&message.to_vec().unwrap(), &names()).is_none());
    }

    #[test]
    fn a_response_is_not_treated_as_a_query() {
        let mut message = Message::new(1, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(
            Name::from_ascii("qbit-proxy.").unwrap(),
            RecordType::A,
        ));
        assert!(answer(&message.to_vec().unwrap(), &names()).is_none());
    }
}
