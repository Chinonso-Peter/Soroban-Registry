use once_cell::sync::Lazy;
use prometheus::{
    histogram_opts, opts, GaugeVec, HistogramVec, IntCounterVec, Registry,
};

pub static REGISTRY: Lazy<Registry> = Lazy::new(Registry::new);

pub static HTTP_REQUESTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        opts!("soroban_http_requests_total", "Total HTTP requests"),
        &["method", "path", "status"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

pub static HTTP_REQUEST_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    let h = HistogramVec::new(
        histogram_opts!(
            "soroban_http_request_duration_seconds",
            "HTTP request latency",
            vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0]
        ),
        &["method", "path"],
    )
    .unwrap();
    REGISTRY.register(Box::new(h.clone())).unwrap();
    h
});

pub static CONTRACTS_PUBLISHED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        opts!("soroban_contracts_published_total", "Contracts published"),
        &["network"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

pub static CONTRACTS_VERIFIED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        opts!("soroban_contracts_verified_total", "Contracts verified"),
        &["status"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

pub static CONTRACTS_PER_PUBLISHER: Lazy<GaugeVec> = Lazy::new(|| {
    let g = GaugeVec::new(
        opts!("soroban_contracts_per_publisher", "Contracts per publisher gauge"),
        &["publisher"],
    )
    .unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
});

pub static VERIFICATION_LATENCY: Lazy<HistogramVec> = Lazy::new(|| {
    let h = HistogramVec::new(
        histogram_opts!(
            "soroban_verification_latency_seconds",
            "Contract verification latency (enables p99 queries)",
            vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        ),
        &["network"],
    )
    .unwrap();
    REGISTRY.register(Box::new(h.clone())).unwrap();
    h
});

pub static DB_POOL_CONNECTIONS: Lazy<prometheus::IntGauge> = Lazy::new(|| {
    let g = prometheus::IntGauge::new(
        "soroban_db_pool_connections",
        "Active DB pool connections",
    )
    .unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
});

pub static DB_QUERY_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    let h = HistogramVec::new(
        histogram_opts!(
            "soroban_db_query_duration_seconds",
            "Database query latency",
            vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
        ),
        &["operation"],
    )
    .unwrap();
    REGISTRY.register(Box::new(h.clone())).unwrap();
    h
});

pub fn init_metrics() {
    // Trigger lazy init of all metrics so they appear in /metrics even before first request
    Lazy::force(&HTTP_REQUESTS_TOTAL);
    Lazy::force(&HTTP_REQUEST_DURATION);
    Lazy::force(&CONTRACTS_PUBLISHED_TOTAL);
    Lazy::force(&CONTRACTS_VERIFIED_TOTAL);
    Lazy::force(&CONTRACTS_PER_PUBLISHER);
    Lazy::force(&VERIFICATION_LATENCY);
    Lazy::force(&DB_POOL_CONNECTIONS);
    Lazy::force(&DB_QUERY_DURATION);
}
