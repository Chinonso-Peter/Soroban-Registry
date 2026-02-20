use axum::{http::StatusCode, response::IntoResponse};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{runtime, trace as sdktrace};
use prometheus::Encoder;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::metrics::REGISTRY;

pub fn init(otlp_endpoint: &str) {
    let exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(otlp_endpoint);

    let tracer_provider = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(exporter)
        .with_trace_config(sdktrace::Config::default().with_resource(
            opentelemetry_sdk::Resource::new(vec![opentelemetry::KeyValue::new(
                "service.name",
                "soroban-registry",
            )]),
        ))
        .install_batch(runtime::Tokio)
        .expect("failed to install OTLP tracer");

    let tracer = tracer_provider.tracer("soroban-registry");

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "api=debug,tower_http=debug".into());

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().json())
        .with(OpenTelemetryLayer::new(tracer))
        .init();
}

pub async fn metrics_handler() -> impl IntoResponse {
    let encoder = prometheus::TextEncoder::new();
    let mut buf = Vec::new();

    if encoder.encode(&REGISTRY.gather(), &mut buf).is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "encoding error").into_response();
    }

    let content_type = encoder.format_type().to_string();
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_str(&content_type)
                .unwrap_or_else(|_| axum::http::HeaderValue::from_static("text/plain")),
        )],
        buf,
    )
        .into_response()
}
