use std::{
    collections::HashMap,
    fs,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{bail, Context};
#[cfg(test)]
use opentelemetry::metrics::MeterProvider as _;
use opentelemetry::{global, metrics::Meter, trace::TracerProvider as _, KeyValue};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{Protocol, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::{
    logs::{BatchConfigBuilder as LogBatchConfigBuilder, BatchLogProcessor, SdkLoggerProvider},
    metrics::{PeriodicReader, SdkMeterProvider},
    trace::{BatchConfigBuilder as SpanBatchConfigBuilder, BatchSpanProcessor, SdkTracerProvider},
    Resource,
};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::registry::LookupSpan;

use crate::config::OtelConfig;

const QUEUE_CAPACITY: usize = 2_048;
const BATCH_CAPACITY: usize = 256;

#[derive(Clone, Debug, Default)]
pub struct ExportStatus {
    successful_exports: Arc<AtomicU64>,
    failed_exports: Arc<AtomicU64>,
    last_success_unix_ms: Arc<AtomicU64>,
    last_failure_unix_ms: Arc<AtomicU64>,
}

impl ExportStatus {
    pub fn successful_exports(&self) -> u64 {
        self.successful_exports.load(Ordering::Relaxed)
    }

    pub fn failed_exports(&self) -> u64 {
        self.failed_exports.load(Ordering::Relaxed)
    }

    pub fn last_success_unix_ms(&self) -> Option<u64> {
        nonzero(self.last_success_unix_ms.load(Ordering::Relaxed))
    }

    pub fn last_failure_unix_ms(&self) -> Option<u64> {
        nonzero(self.last_failure_unix_ms.load(Ordering::Relaxed))
    }

    fn success(&self) {
        self.successful_exports.fetch_add(1, Ordering::Relaxed);
        self.last_success_unix_ms
            .store(crate::runtime::unix_ms(), Ordering::Relaxed);
    }

    fn failure(&self) {
        self.failed_exports.fetch_add(1, Ordering::Relaxed);
        self.last_failure_unix_ms
            .store(crate::runtime::unix_ms(), Ordering::Relaxed);
    }
}

fn nonzero(value: u64) -> Option<u64> {
    (value != 0).then_some(value)
}

#[derive(Debug)]
struct TrackingSpanExporter {
    inner: opentelemetry_otlp::SpanExporter,
    status: ExportStatus,
}

impl opentelemetry_sdk::trace::SpanExporter for TrackingSpanExporter {
    async fn export(
        &self,
        batch: Vec<opentelemetry_sdk::trace::SpanData>,
    ) -> opentelemetry_sdk::error::OTelSdkResult {
        let result = opentelemetry_sdk::trace::SpanExporter::export(&self.inner, batch).await;
        if result.is_ok() {
            self.status.success();
        } else {
            self.status.failure();
        }
        result
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> opentelemetry_sdk::error::OTelSdkResult {
        opentelemetry_sdk::trace::SpanExporter::shutdown_with_timeout(&self.inner, timeout)
    }

    fn force_flush(&self) -> opentelemetry_sdk::error::OTelSdkResult {
        opentelemetry_sdk::trace::SpanExporter::force_flush(&self.inner)
    }

    fn set_resource(&mut self, resource: &Resource) {
        opentelemetry_sdk::trace::SpanExporter::set_resource(&mut self.inner, resource);
    }
}

#[derive(Debug)]
struct TrackingLogExporter {
    inner: opentelemetry_otlp::LogExporter,
    status: ExportStatus,
}

impl opentelemetry_sdk::logs::LogExporter for TrackingLogExporter {
    async fn export(
        &self,
        batch: opentelemetry_sdk::logs::LogBatch<'_>,
    ) -> opentelemetry_sdk::error::OTelSdkResult {
        let result = opentelemetry_sdk::logs::LogExporter::export(&self.inner, batch).await;
        if result.is_ok() {
            self.status.success();
        } else {
            self.status.failure();
        }
        result
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> opentelemetry_sdk::error::OTelSdkResult {
        opentelemetry_sdk::logs::LogExporter::shutdown_with_timeout(&self.inner, timeout)
    }

    fn event_enabled(
        &self,
        level: opentelemetry::logs::Severity,
        target: &str,
        name: Option<&str>,
    ) -> bool {
        opentelemetry_sdk::logs::LogExporter::event_enabled(&self.inner, level, target, name)
    }

    fn set_resource(&mut self, resource: &Resource) {
        opentelemetry_sdk::logs::LogExporter::set_resource(&mut self.inner, resource);
    }
}

#[derive(Debug)]
struct TrackingMetricExporter {
    inner: opentelemetry_otlp::MetricExporter,
    status: ExportStatus,
}

impl opentelemetry_sdk::metrics::exporter::PushMetricExporter for TrackingMetricExporter {
    async fn export(
        &self,
        metrics: &opentelemetry_sdk::metrics::data::ResourceMetrics,
    ) -> opentelemetry_sdk::error::OTelSdkResult {
        let result =
            opentelemetry_sdk::metrics::exporter::PushMetricExporter::export(&self.inner, metrics)
                .await;
        if result.is_ok() {
            self.status.success();
        } else {
            self.status.failure();
        }
        result
    }

    fn force_flush(&self) -> opentelemetry_sdk::error::OTelSdkResult {
        opentelemetry_sdk::metrics::exporter::PushMetricExporter::force_flush(&self.inner)
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> opentelemetry_sdk::error::OTelSdkResult {
        opentelemetry_sdk::metrics::exporter::PushMetricExporter::shutdown_with_timeout(
            &self.inner,
            timeout,
        )
    }

    fn temporality(&self) -> opentelemetry_sdk::metrics::Temporality {
        opentelemetry_sdk::metrics::exporter::PushMetricExporter::temporality(&self.inner)
    }
}

pub struct TelemetryGuard {
    tracer_provider: SdkTracerProvider,
    meter_provider: SdkMeterProvider,
    logger_provider: SdkLoggerProvider,
    pub status: ExportStatus,
    timeout: Duration,
}

#[derive(Clone)]
pub struct TelemetryMetrics {
    client_bytes: opentelemetry::metrics::Gauge<u64>,
    client_packets: opentelemetry::metrics::Gauge<u64>,
    export_successes: opentelemetry::metrics::Gauge<u64>,
    export_failures: opentelemetry::metrics::Gauge<u64>,
    vpn_server_rtt: opentelemetry::metrics::Gauge<f64>,
}

impl TelemetryMetrics {
    pub fn new() -> Self {
        Self::from_meter(global::meter("egressy"))
    }

    fn from_meter(meter: Meter) -> Self {
        Self {
            client_bytes: meter
                .u64_gauge("egressy.client.traffic.bytes")
                .with_description("Current gateway-observed workload traffic totals")
                .build(),
            client_packets: meter
                .u64_gauge("egressy.client.traffic.packets")
                .with_description("Current gateway-observed workload packet totals")
                .build(),
            export_successes: meter
                .u64_gauge("egressy.otel.exports.success")
                .with_description("Successful OTLP export calls")
                .build(),
            export_failures: meter
                .u64_gauge("egressy.otel.exports.failure")
                .with_description("Failed OTLP export calls")
                .build(),
            vpn_server_rtt: meter
                .f64_gauge("egressy.vpn_server.endpoint.rtt")
                .with_unit("ms")
                .with_description("Underlay ICMP RTT to the active WireGuard endpoint")
                .build(),
        }
    }

    pub fn record_client(
        &self,
        usage_id: &str,
        download_bytes: u64,
        upload_bytes: u64,
        download_packets: u64,
        upload_packets: u64,
    ) {
        for (direction, bytes, packets) in [
            ("download", download_bytes, download_packets),
            ("upload", upload_bytes, upload_packets),
        ] {
            let attributes = [
                KeyValue::new("egressy.usage.id", bounded_attribute(usage_id)),
                KeyValue::new("network.io.direction", direction),
            ];
            self.client_bytes.record(bytes, &attributes);
            self.client_packets.record(packets, &attributes);
        }
    }

    pub fn record_export_status(&self, status: &ExportStatus) {
        self.export_successes
            .record(status.successful_exports(), &[]);
        self.export_failures.record(status.failed_exports(), &[]);
    }

    pub fn record_vpn_server_rtt(&self, endpoint_family: &str, rtt_ms: f64) {
        self.vpn_server_rtt.record(
            rtt_ms,
            &[KeyValue::new(
                "network.type",
                bounded_attribute(endpoint_family),
            )],
        );
    }
}

fn bounded_attribute(value: &str) -> String {
    value.chars().take(128).collect()
}

impl TelemetryGuard {
    pub fn shutdown(&self) {
        let _ = self.tracer_provider.force_flush();
        let _ = self.logger_provider.force_flush();
        let _ = self.meter_provider.force_flush();
        let _ = self.tracer_provider.shutdown_with_timeout(self.timeout);
        let _ = self.logger_provider.shutdown_with_timeout(self.timeout);
        let _ = self.meter_provider.shutdown_with_timeout(self.timeout);
    }
}

pub struct TelemetryLayers<S>
where
    S: tracing::Subscriber + for<'span> LookupSpan<'span>,
{
    pub trace: OpenTelemetryLayer<S, opentelemetry_sdk::trace::Tracer>,
    pub logs: OpenTelemetryTracingBridge<SdkLoggerProvider, opentelemetry_sdk::logs::SdkLogger>,
    pub guard: TelemetryGuard,
}

pub fn build<S>(config: &OtelConfig) -> anyhow::Result<Option<TelemetryLayers<S>>>
where
    S: tracing::Subscriber + for<'span> LookupSpan<'span>,
{
    if !config.enabled {
        return Ok(None);
    }
    let timeout = Duration::from_secs(config.timeout_seconds);
    let headers = load_headers(config.headers_path.as_deref())?;
    let endpoint = config.endpoint.trim_end_matches('/');
    let status = ExportStatus::default();
    let resource = Resource::builder()
        .with_service_name(config.service_name.clone())
        .with_attributes([KeyValue::new("service.version", env!("CARGO_PKG_VERSION"))])
        .build();

    let span_exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(signal_endpoint(endpoint, "traces"))
        .with_timeout(timeout)
        .with_headers(headers.clone())
        .build()?;
    let span_processor = BatchSpanProcessor::builder(TrackingSpanExporter {
        inner: span_exporter,
        status: status.clone(),
    })
    .with_batch_config(
        SpanBatchConfigBuilder::default()
            .with_max_queue_size(QUEUE_CAPACITY)
            .with_max_export_batch_size(BATCH_CAPACITY)
            .with_scheduled_delay(Duration::from_secs(5))
            .build(),
    )
    .build();
    let tracer_provider = SdkTracerProvider::builder()
        .with_resource(resource.clone())
        .with_span_processor(span_processor)
        .build();
    let tracer = tracer_provider.tracer("egressy");

    let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(signal_endpoint(endpoint, "metrics"))
        .with_timeout(timeout)
        .with_headers(headers.clone())
        .build()?;
    let reader = PeriodicReader::builder(TrackingMetricExporter {
        inner: metric_exporter,
        status: status.clone(),
    })
    .with_interval(Duration::from_secs(15))
    .build();
    let meter_provider = SdkMeterProvider::builder()
        .with_resource(resource.clone())
        .with_reader(reader)
        .build();
    global::set_meter_provider(meter_provider.clone());

    let log_exporter = opentelemetry_otlp::LogExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(signal_endpoint(endpoint, "logs"))
        .with_timeout(timeout)
        .with_headers(headers)
        .build()?;
    let log_processor = BatchLogProcessor::builder(TrackingLogExporter {
        inner: log_exporter,
        status: status.clone(),
    })
    .with_batch_config(
        LogBatchConfigBuilder::default()
            .with_max_queue_size(QUEUE_CAPACITY)
            .with_max_export_batch_size(BATCH_CAPACITY)
            .with_scheduled_delay(Duration::from_secs(5))
            .build(),
    )
    .build();
    let logger_provider = SdkLoggerProvider::builder()
        .with_resource(resource)
        .with_log_processor(log_processor)
        .build();

    Ok(Some(TelemetryLayers {
        trace: tracing_opentelemetry::layer().with_tracer(tracer),
        logs: OpenTelemetryTracingBridge::new(&logger_provider),
        guard: TelemetryGuard {
            tracer_provider,
            meter_provider,
            logger_provider,
            status,
            timeout,
        },
    }))
}

fn signal_endpoint(base: &str, signal: &str) -> String {
    if base.ends_with(&format!("/v1/{signal}")) {
        base.to_owned()
    } else {
        format!("{base}/v1/{signal}")
    }
}

fn load_headers(path: Option<&str>) -> anyhow::Result<HashMap<String, String>> {
    let Some(path) = path else {
        return Ok(HashMap::new());
    };
    let raw = fs::read_to_string(path).context("reading protected OTEL headers file")?;
    let mut headers = HashMap::new();
    for entry in raw.lines().flat_map(|line| line.split(',')) {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Some((name, value)) = entry.split_once('=') else {
            bail!("OTEL header entries must use name=value syntax");
        };
        let name = name.trim();
        let value = value.trim();
        if name.is_empty()
            || value.is_empty()
            || name.len() > 128
            || value.len() > 4_096
            || !name
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '-')
            || value.contains(['\r', '\n'])
        {
            bail!("OTEL header entry is empty, unsafe, or too long");
        }
        headers.insert(name.to_owned(), value.to_owned());
    }
    Ok(headers)
}

#[cfg(test)]
mod tests {
    use std::{future::IntoFuture, sync::Mutex};

    use axum::{
        body::Bytes,
        extract::State,
        http::{StatusCode, Uri},
        routing::post,
        Router,
    };
    use tracing_subscriber::layer::SubscriberExt;

    use super::*;

    #[test]
    fn disabled_configuration_builds_no_exporters() {
        let layers = build::<tracing_subscriber::Registry>(&OtelConfig::default()).unwrap();
        assert!(layers.is_none());
    }

    #[test]
    fn signal_endpoints_append_only_when_needed() {
        assert_eq!(
            signal_endpoint("https://collector.example.com:4318", "traces"),
            "https://collector.example.com:4318/v1/traces"
        );
        assert_eq!(
            signal_endpoint("https://collector.example.com:4318/v1/traces", "traces"),
            "https://collector.example.com:4318/v1/traces"
        );
    }

    #[test]
    fn protected_header_parser_rejects_line_injection() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp.path(), "Authorization=Bearer safe\nInjected: bad").unwrap();
        assert!(load_headers(temp.path().to_str()).is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn enabled_export_reaches_only_configured_otlp_signal_paths() {
        async fn receive(
            State(paths): State<Arc<Mutex<Vec<String>>>>,
            uri: Uri,
            _body: Bytes,
        ) -> StatusCode {
            paths.lock().unwrap().push(uri.path().to_owned());
            StatusCode::OK
        }

        let paths = Arc::new(Mutex::new(Vec::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(
            axum::serve(
                listener,
                Router::new()
                    .route("/{*path}", post(receive))
                    .with_state(paths.clone()),
            )
            .into_future(),
        );
        let config = OtelConfig {
            enabled: true,
            endpoint: format!("http://{address}"),
            insecure: true,
            timeout_seconds: 2,
            ..OtelConfig::default()
        };
        let layers = build::<tracing_subscriber::Registry>(&config)
            .unwrap()
            .unwrap();
        let subscriber = tracing_subscriber::registry()
            .with(layers.trace)
            .with(layers.logs);
        tracing::subscriber::with_default(subscriber, || {
            tracing::info_span!("otel_test_span").in_scope(|| {
                tracing::info!(component = "test", "safe OTEL test event");
            });
        });
        // Use this build's provider directly: process-global providers can be
        // replaced by another parallel test.
        let metrics = TelemetryMetrics::from_meter(layers.guard.meter_provider.meter("egressy"));
        metrics.record_client("test:client", 10, 5, 2, 1);
        assert!(layers.guard.tracer_provider.force_flush().is_ok());
        assert!(layers.guard.logger_provider.force_flush().is_ok());
        assert!(layers.guard.meter_provider.force_flush().is_ok());

        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            let observed = paths.lock().unwrap().clone();
            if ["/v1/traces", "/v1/logs", "/v1/metrics"]
                .iter()
                .all(|path| observed.iter().any(|seen| seen == path))
            {
                assert!(observed.iter().all(|path| matches!(
                    path.as_str(),
                    "/v1/traces" | "/v1/logs" | "/v1/metrics"
                )));
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "missing OTLP signal requests: {observed:?}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        layers.guard.shutdown();
        server.abort();
    }

    #[test]
    fn unavailable_collector_is_bounded_and_records_failure() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let config = OtelConfig {
            enabled: true,
            endpoint: format!("http://{address}"),
            insecure: true,
            timeout_seconds: 1,
            ..OtelConfig::default()
        };
        let layers = build::<tracing_subscriber::Registry>(&config)
            .unwrap()
            .unwrap();
        let subscriber = tracing_subscriber::registry()
            .with(layers.trace)
            .with(layers.logs);
        tracing::subscriber::with_default(subscriber, || {
            tracing::info_span!("collector_outage").in_scope(|| {
                tracing::info!("safe collector outage event");
            });
        });
        let started = std::time::Instant::now();
        let _ = layers.guard.tracer_provider.force_flush();
        let _ = layers.guard.logger_provider.force_flush();
        assert!(started.elapsed() < Duration::from_secs(4));
        assert!(layers.guard.status.failed_exports() > 0);
        layers.guard.shutdown();
    }
}
