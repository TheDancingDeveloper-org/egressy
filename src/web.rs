use std::{convert::Infallible, time::Duration};

use axum::{
    extract::{Extension, Query, State},
    http::{header, StatusCode},
    response::{sse::Event, Html, IntoResponse, Response, Sse},
    routing::{get, post},
    Json, Router,
};
use futures_util::Stream;
use tokio_stream::{wrappers::BroadcastStream, StreamExt};
use tower_http::trace::TraceLayer;

use crate::{
    control::StatePublisher,
    domain::{Availability, CanonicalSnapshot, CheckStatus, Transition},
    history::{
        EventHistoryQuery, HistoryQueryError, HistoryStore, UsageHistoryQuery,
        VpnServerHistoryQuery,
    },
    runtime::SharedHistory,
    state::{AppState, SharedState},
};

const INDEX: &str = include_str!("../ui/dist/index.html");
const OPENAPI: &str = include_str!("../openapi/v2.json");

#[derive(Clone)]
pub struct WebState {
    legacy: SharedState,
    publisher: StatePublisher,
    history: SharedHistory,
}

pub fn router(
    legacy: SharedState,
    publisher: StatePublisher,
    history: SharedHistory,
    notifications: crate::notifications::NotificationManager,
) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/v1/status", get(v1_status))
        .route("/api/v2/status", get(v2_status))
        .route("/api/v2/isolation-policy", get(isolation_policy))
        .route("/api/v2/events", get(events))
        .route("/api/v2/history/usage", get(usage_history))
        .route("/api/v2/history/events", get(event_history))
        .route("/api/v2/history/vpn-server", get(vpn_server_history))
        .route(
            "/api/v2/settings/notifications",
            get(notification_settings).put(update_notification_settings),
        )
        .route(
            "/api/v2/settings/notifications/test",
            post(test_notification),
        )
        .route("/api/v2/openapi.json", get(openapi))
        .route("/metrics", get(metrics))
        .route("/healthz", get(health))
        .route("/livez", get(liveness))
        .route("/readyz", get(readiness))
        .layer(TraceLayer::new_for_http())
        .layer(Extension(notifications))
        .with_state(WebState {
            legacy,
            publisher,
            history,
        })
}

async fn notification_settings(
    Extension(notifications): Extension<crate::notifications::NotificationManager>,
) -> Json<crate::notifications::NotificationSettingsView> {
    Json(notifications.view().await)
}

async fn update_notification_settings(
    State(state): State<WebState>,
    Extension(notifications): Extension<crate::notifications::NotificationManager>,
    Json(input): Json<crate::notifications::NotificationSettingsInput>,
) -> Response {
    match notifications.update(input, &state.history).await {
        Ok(settings) => Json(settings).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_notification_settings",
                "message": error.to_string()
            })),
        )
            .into_response(),
    }
}

async fn test_notification(
    Extension(notifications): Extension<crate::notifications::NotificationManager>,
) -> Response {
    match notifications.test().await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => {
            tracing::warn!("test notification failed");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": "notification_delivery_failed"})),
            )
                .into_response()
        }
    }
}

async fn usage_history(
    State(state): State<WebState>,
    Query(query): Query<UsageHistoryQuery>,
) -> Response {
    history_response(
        &state,
        |store| async move { store.usage_history(query).await },
    )
    .await
}

async fn event_history(
    State(state): State<WebState>,
    Query(query): Query<EventHistoryQuery>,
) -> Response {
    history_response(
        &state,
        |store| async move { store.event_history(query).await },
    )
    .await
}

async fn vpn_server_history(
    State(state): State<WebState>,
    Query(query): Query<VpnServerHistoryQuery>,
) -> Response {
    history_response(&state, |store| async move {
        store.vpn_server_history(query).await
    })
    .await
}

async fn history_response<T, F, Fut>(state: &WebState, query: F) -> Response
where
    T: serde::Serialize,
    F: FnOnce(HistoryStore) -> Fut,
    Fut: std::future::Future<Output = Result<T, HistoryQueryError>>,
{
    let Some(store) = state.history.read().await.clone() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "history_unavailable"})),
        )
            .into_response();
    };
    match query(store).await {
        Ok(response) => Json(response).into_response(),
        Err(HistoryQueryError::Invalid(message)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid_history_query", "message": message})),
        )
            .into_response(),
        Err(HistoryQueryError::Unavailable(error)) => {
            tracing::warn!(%error, "history read failed; marking storage unavailable");
            *state.history.write().await = None;
            state
                .publisher
                .observe(
                    "history.persistence",
                    CheckStatus::Degraded,
                    crate::domain::Impact::Advisory,
                    "history.database_unavailable",
                    "App-owned history is unavailable; current-state operation continues",
                    None,
                    None,
                )
                .await;
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "history_unavailable"})),
            )
                .into_response()
        }
    }
}

async fn index() -> Html<&'static str> {
    Html(INDEX)
}

async fn openapi() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "application/json")], OPENAPI)
}

async fn v1_status(State(state): State<WebState>) -> Json<AppState> {
    Json(state.legacy.read().await.clone())
}

async fn v2_status(State(state): State<WebState>) -> Json<CanonicalSnapshot> {
    Json(state.publisher.subscribe().borrow().clone())
}

async fn isolation_policy(
    State(state): State<WebState>,
) -> Json<crate::isolation::IsolationPolicy> {
    Json(
        state
            .publisher
            .subscribe()
            .borrow()
            .isolation_policy
            .clone(),
    )
}

async fn metrics(State(state): State<WebState>) -> Response {
    let snapshot = state.publisher.subscribe().borrow().clone();
    let mut output = String::from(
        "# HELP egressy_client_traffic_bytes_total Per-client traffic observed by gateway nftables.\n\
# TYPE egressy_client_traffic_bytes_total counter\n",
    );
    for client in snapshot.clients.values() {
        let id = prometheus_label_value(&client.container_id);
        for (direction, value) in [
            ("download", client.traffic.downloaded_bytes),
            ("upload", client.traffic.uploaded_bytes),
        ] {
            output.push_str(&format!(
                "egressy_client_traffic_bytes_total{{container_id=\"{id}\",direction=\"{direction}\"}} {value}\n"
            ));
        }
    }
    output.push_str(
        "# HELP egressy_client_traffic_packets_total Per-client packets observed by gateway nftables.\n\
# TYPE egressy_client_traffic_packets_total counter\n",
    );
    for client in snapshot.clients.values() {
        let id = prometheus_label_value(&client.container_id);
        for (direction, value) in [
            ("download", client.traffic.download_packets),
            ("upload", client.traffic.upload_packets),
        ] {
            output.push_str(&format!(
                "egressy_client_traffic_packets_total{{container_id=\"{id}\",direction=\"{direction}\"}} {value}\n"
            ));
        }
    }
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        output,
    )
        .into_response()
}

fn prometheus_label_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

async fn events(
    State(state): State<WebState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = BroadcastStream::new(state.publisher.subscribe_events()).filter_map(|result| {
        result
            .ok()
            .and_then(|transition| event(&transition).ok())
            .map(Ok)
    });
    Sse::new(stream)
        .keep_alive(axum::response::sse::KeepAlive::new().interval(Duration::from_secs(15)))
}

fn event(transition: &Transition) -> Result<Event, serde_json::Error> {
    Ok(Event::default()
        .id(transition.sequence.to_string())
        .event("transition")
        .data(serde_json::to_string(transition)?))
}

async fn health(State(state): State<WebState>) -> impl IntoResponse {
    let state = state.legacy.read().await;
    text_status(state.tunnel.up, "ok\n", "tunnel down\n")
}

async fn liveness() -> impl IntoResponse {
    text_status(true, "ok\n", "unreachable\n")
}

async fn readiness(State(state): State<WebState>) -> impl IntoResponse {
    let snapshot = state.publisher.subscribe().borrow().clone();
    let ready = !matches!(
        snapshot.availability,
        Availability::Starting | Availability::Unavailable
    ) && snapshot
        .checks
        .values()
        .filter(|check| check.impact == crate::domain::Impact::Critical)
        .all(|check| check.status != CheckStatus::Failed);
    text_status(ready, "ready\n", "data_plane_not_ready\n")
}

fn text_status(ok: bool, success: &'static str, failure: &'static str) -> impl IntoResponse {
    (
        if ok {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        [(header::CONTENT_TYPE, "text/plain")],
        if ok { success } else { failure },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{CheckStatus, Impact};

    #[tokio::test]
    async fn notification_settings_handler_persists_and_returns_only_masked_values() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = crate::history::HistoryStore::open(&crate::config::PersistenceConfig {
            path: temp.path().join("history.sqlite3").display().to_string(),
            ..crate::config::PersistenceConfig::default()
        })
        .unwrap();
        let history = std::sync::Arc::new(tokio::sync::RwLock::new(Some(store.clone())));
        let notifications = crate::notifications::NotificationManager::start(history.clone()).await;
        let state = WebState {
            legacy: std::sync::Arc::new(tokio::sync::RwLock::new(AppState::default())),
            publisher: StatePublisher::new(CanonicalSnapshot::default()),
            history,
        };
        let response = update_notification_settings(
            State(state),
            Extension(notifications.clone()),
            Json(crate::notifications::NotificationSettingsInput {
                enabled: true,
                provider: crate::notifications::NotificationProvider::Generic,
                webhook_url: "https://hooks.example.com/private/token".into(),
                telegram_chat_id: String::new(),
                hmac_secret: "test-secret".into(),
                timeout_seconds: 5,
                rtt_threshold_ms: 75.0,
                alert_stack_started: true,
                alert_vpn_disconnected: true,
                alert_vpn_reconnected: true,
                alert_rtt_above_threshold: true,
                alert_diagnostic_failed: true,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("https://hooks.example.com/…"));
        assert!(!body.contains("private/token"));
        assert!(!body.contains("test-secret"));
        let Json(view) = notification_settings(Extension(notifications)).await;
        assert!(view.enabled);
        assert_eq!(view.rtt_threshold_ms, 75.0);
        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn history_handler_returns_persisted_usage_and_unavailable_is_explicit() {
        let unavailable = WebState {
            legacy: std::sync::Arc::new(tokio::sync::RwLock::new(AppState::default())),
            publisher: StatePublisher::new(CanonicalSnapshot::default()),
            history: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        };
        assert_eq!(
            usage_history(State(unavailable), Query(UsageHistoryQuery::default()))
                .await
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );

        let temp = tempfile::TempDir::new().unwrap();
        let store = crate::history::HistoryStore::open(&crate::config::PersistenceConfig {
            path: temp.path().join("history.sqlite3").display().to_string(),
            ..crate::config::PersistenceConfig::default()
        })
        .unwrap();
        let now = crate::runtime::unix_ms();
        assert!(store.record_usage(crate::history::UsageObservation {
            sampled_at_unix_ms: now,
            usage_id: "test:client".into(),
            usage_id_source: crate::state::UsageIdentitySource::ExplicitLabel,
            container_id: "container-a".into(),
            ipv4_address: "172.30.0.10".into(),
            name: "client".into(),
            download_bytes: 100,
            upload_bytes: 50,
            download_packets: 2,
            upload_packets: 1,
        }));
        store.flush().await.unwrap();
        let state = WebState {
            legacy: std::sync::Arc::new(tokio::sync::RwLock::new(AppState::default())),
            publisher: StatePublisher::new(CanonicalSnapshot::default()),
            history: std::sync::Arc::new(tokio::sync::RwLock::new(Some(store.clone()))),
        };
        let response = usage_history(
            State(state),
            Query(UsageHistoryQuery {
                from_unix_ms: Some(now.saturating_sub(60_000)),
                to_unix_ms: Some(now + 60_000),
                usage_id: Some("test:client".into()),
                ..UsageHistoryQuery::default()
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn invalid_history_query_is_400_but_storage_failures_are_503() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = crate::history::HistoryStore::open(&crate::config::PersistenceConfig {
            path: temp.path().join("history.sqlite3").display().to_string(),
            ..crate::config::PersistenceConfig::default()
        })
        .unwrap();
        let state = WebState {
            legacy: std::sync::Arc::new(tokio::sync::RwLock::new(AppState::default())),
            publisher: StatePublisher::new(CanonicalSnapshot::default()),
            history: std::sync::Arc::new(tokio::sync::RwLock::new(Some(store.clone()))),
        };

        let invalid = usage_history(
            State(state.clone()),
            Query(UsageHistoryQuery {
                from_unix_ms: Some(2),
                to_unix_ms: Some(1),
                ..UsageHistoryQuery::default()
            }),
        )
        .await;
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
        assert!(state.history.read().await.is_some());

        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn corrupt_history_database_returns_503_and_degrades_persistence() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("history.sqlite3");
        let store = crate::history::HistoryStore::open(&crate::config::PersistenceConfig {
            path: path.display().to_string(),
            ..crate::config::PersistenceConfig::default()
        })
        .unwrap();
        store.flush().await.unwrap();
        std::fs::write(&path, b"not a sqlite database").unwrap();

        let state = WebState {
            legacy: std::sync::Arc::new(tokio::sync::RwLock::new(AppState::default())),
            publisher: StatePublisher::new(CanonicalSnapshot::default()),
            history: std::sync::Arc::new(tokio::sync::RwLock::new(Some(store))),
        };
        let response =
            usage_history(State(state.clone()), Query(UsageHistoryQuery::default())).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(state.history.read().await.is_none());
        assert_eq!(
            state.publisher.subscribe().borrow().checks["history.persistence"].reason_code,
            "history.database_unavailable"
        );
    }

    #[tokio::test]
    async fn read_only_and_locked_storage_errors_return_503() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = crate::history::HistoryStore::open(&crate::config::PersistenceConfig {
            path: temp.path().join("history.sqlite3").display().to_string(),
            ..crate::config::PersistenceConfig::default()
        })
        .unwrap();
        let state = WebState {
            legacy: std::sync::Arc::new(tokio::sync::RwLock::new(AppState::default())),
            publisher: StatePublisher::new(CanonicalSnapshot::default()),
            history: std::sync::Arc::new(tokio::sync::RwLock::new(Some(store.clone()))),
        };
        for message in ["attempt to write a readonly database", "database is locked"] {
            *state.history.write().await = Some(store.clone());
            let response = history_response::<serde_json::Value, _, _>(&state, |_store| async {
                Err(HistoryQueryError::Unavailable(anyhow::anyhow!(message)))
            })
            .await;
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
        store.shutdown().await.unwrap();
    }

    #[test]
    fn serializes_correlated_port_verification_contract() {
        let mut snapshot = CanonicalSnapshot::default();
        snapshot.port_forward.phase = crate::domain::PortForwardPhase::Verified;
        snapshot.port_forward.external_port = Some(45678);
        snapshot.port_forward.lease_acquired_at_unix_ms = Some(1_000);
        snapshot.port_forward.dnat_installed = true;
        snapshot.port_forward.externally_verified = Some(true);
        snapshot.external_probe.forwarded_port = Some(45678);
        snapshot.external_probe.lease_acquired_at_unix_ms = Some(1_000);
        snapshot.external_probe.request_started_at_unix_ms = Some(1_100);

        let serialized = serde_json::to_value(snapshot).unwrap();
        assert_eq!(serialized["port_forward"]["phase"], "verified");
        assert_eq!(serialized["port_forward"]["externally_verified"], true);
        assert_eq!(serialized["external_probe"]["forwarded_port"], 45678);
        assert_eq!(
            serialized["external_probe"]["lease_acquired_at_unix_ms"],
            1_000
        );
        assert_eq!(
            serialized["external_probe"]["request_started_at_unix_ms"],
            1_100
        );
        assert!(serialized.to_string().find("PrivateKey").is_none());
    }

    #[test]
    fn serializes_typed_route_intent_contract() {
        let client = route_intent_client();
        let serialized = serde_json::to_value(client).unwrap();
        assert_eq!(serialized["route_intent"]["status"], "mismatch");
        assert_eq!(serialized["route_intent"]["ipv4_default_network"], "app");
        assert_eq!(serialized["compliant"], false);
    }

    #[tokio::test]
    async fn isolation_policy_handler_returns_only_safe_contract_fields() {
        let snapshot = CanonicalSnapshot {
            isolation_policy: crate::isolation::build_policy(
                "vpn-egress",
                "br-vpn-egress",
                "172.30.0.0/24".parse().unwrap(),
                vec![crate::isolation::IsolationCandidate {
                    container_id: "safe-container-id".to_owned(),
                    name: "client".to_owned(),
                    ipv4_address: "172.30.0.10".parse().unwrap(),
                    isolation_id: Some("client".to_owned()),
                    allow: None,
                }],
                123,
            ),
            ..CanonicalSnapshot::default()
        };
        let state = WebState {
            legacy: std::sync::Arc::new(tokio::sync::RwLock::new(AppState::default())),
            publisher: StatePublisher::new(snapshot),
            history: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        };
        let Json(policy) = isolation_policy(State(state)).await;
        let value = serde_json::to_value(policy).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["participants"][0]["isolation_id"], "client");
        let serialized = value.to_string();
        assert!(!serialized.contains("labels"));
        assert!(!serialized.contains("environment"));
        assert!(!serialized.contains("PrivateKey"));
    }

    #[tokio::test]
    async fn metrics_are_bounded_to_current_clients_and_escape_labels() {
        let mut snapshot = CanonicalSnapshot::default();
        let mut client = route_intent_client();
        client.container_id = "unsafe\"id\\line\n".to_owned();
        client.traffic.downloaded_bytes = 100;
        client.traffic.uploaded_bytes = 200;
        client.traffic.download_packets = 3;
        client.traffic.upload_packets = 4;
        snapshot.clients.insert(client.container_id.clone(), client);
        let state = WebState {
            legacy: std::sync::Arc::new(tokio::sync::RwLock::new(AppState::default())),
            publisher: StatePublisher::new(snapshot),
            history: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        };

        let response = metrics(State(state)).await;
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("container_id=\"unsafe\\\"id\\\\line\\n\""));
        assert!(!body.contains("name="));
        assert!(body.contains("direction=\"download\"} 100"));
        assert!(body.contains("direction=\"upload\"} 200"));
        assert_eq!(
            body.matches("egressy_client_traffic_bytes_total{").count(),
            2
        );
        assert_eq!(
            body.matches("egressy_client_traffic_packets_total{")
                .count(),
            2
        );
    }

    fn route_intent_client() -> crate::state::ClientState {
        crate::state::ClientState {
            container_id: "safe-id".to_owned(),
            usage_id: "test:client".to_owned(),
            usage_id_source: crate::state::UsageIdentitySource::ExplicitLabel,
            name: "client".to_owned(),
            ipv4_address: "172.30.0.10".parse().unwrap(),
            port_forward_target: false,
            target_port: None,
            compliant: false,
            compliance_message: "Docker declares an alternate IPv4 default network".to_owned(),
            running: true,
            ipv6_address: None,
            networks: vec!["app".to_owned(), "vpn-egress".to_owned()],
            port_forward_label_valid: true,
            route_intent: crate::state::RouteIntentState {
                status: crate::state::RouteIntentStatus::Mismatch,
                ipv4_default_network: Some("app".to_owned()),
                ipv6_default_network: None,
                egress_gateway_priority: Some(100),
                gateway_priorities: [
                    ("app".to_owned(), Some(200)),
                    ("vpn-egress".to_owned(), Some(100)),
                ]
                .into(),
                reason_code: "route_intent.alternate_selected".to_owned(),
                safe_message: "Docker declares an alternate network".to_owned(),
            },
            traffic: crate::state::ClientTrafficState::default(),
        }
    }

    #[tokio::test]
    async fn v1_handler_adds_route_intent_with_mismatch_compliance() {
        let mut legacy = AppState::default();
        legacy
            .clients
            .insert("safe-id".to_owned(), route_intent_client());
        let state = WebState {
            legacy: std::sync::Arc::new(tokio::sync::RwLock::new(legacy)),
            publisher: StatePublisher::new(CanonicalSnapshot::default()),
            history: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        };

        let Json(response) = v1_status(State(state)).await;
        let client = &response.clients["safe-id"];
        assert_eq!(
            client.route_intent.status,
            crate::state::RouteIntentStatus::Mismatch
        );
        assert!(!client.compliant);
    }

    #[tokio::test]
    async fn v2_handler_returns_correlated_port_verification() {
        let mut snapshot = CanonicalSnapshot::default();
        snapshot.port_forward.phase = crate::domain::PortForwardPhase::Verified;
        snapshot.port_forward.externally_verified = Some(true);
        snapshot.external_probe.forwarded_port = Some(45678);
        let publisher = StatePublisher::new(snapshot);
        let state = WebState {
            legacy: std::sync::Arc::new(tokio::sync::RwLock::new(AppState::default())),
            publisher,
            history: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        };

        let Json(response) = v2_status(State(state)).await;
        assert_eq!(
            response.port_forward.phase,
            crate::domain::PortForwardPhase::Verified
        );
        assert_eq!(response.port_forward.externally_verified, Some(true));
        assert_eq!(response.external_probe.forwarded_port, Some(45678));
    }

    #[tokio::test]
    async fn optional_verification_failure_does_not_change_health_or_readiness() {
        let legacy: SharedState = std::sync::Arc::new(tokio::sync::RwLock::new(AppState {
            tunnel: crate::state::TunnelState {
                up: true,
                ..crate::state::TunnelState::default()
            },
            ..AppState::default()
        }));
        let mut snapshot = CanonicalSnapshot::default();
        for id in ["gateway.firewall", "gateway.routes"] {
            snapshot.checks.insert(
                id.to_owned(),
                crate::domain::SubsystemCheck {
                    status: CheckStatus::Healthy,
                    ..crate::domain::SubsystemCheck::pending(id, Impact::Critical, 1)
                },
            );
        }
        snapshot.checks.insert(
            "port_forward.verification".to_owned(),
            crate::domain::SubsystemCheck {
                status: CheckStatus::Degraded,
                ..crate::domain::SubsystemCheck::pending(
                    "port_forward.verification",
                    Impact::Optional,
                    1,
                )
            },
        );
        snapshot.derive_aggregate();
        let state = WebState {
            legacy,
            publisher: StatePublisher::new(snapshot),
            history: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        };

        assert_eq!(
            health(State(state.clone())).await.into_response().status(),
            StatusCode::OK
        );
        assert_eq!(
            readiness(State(state)).await.into_response().status(),
            StatusCode::OK
        );
    }

    #[test]
    fn serializes_transition_for_sse_without_secrets() {
        let transition = Transition {
            sequence: 1,
            timestamp_unix_ms: 2,
            component: "wireguard.handshake".into(),
            from_status: CheckStatus::Pending,
            to_status: CheckStatus::Healthy,
            reason_code: "wireguard.handshake_recent".into(),
            safe_message: "Recent handshake observed".into(),
            recovery_attempt: None,
        };
        let serialized = serde_json::to_string(&transition).unwrap();
        assert!(!serialized.contains("PrivateKey"));
        assert_eq!(Impact::Critical, Impact::Critical);
    }
}
