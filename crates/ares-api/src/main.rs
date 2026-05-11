//! ARES HTTP API — thin wrapper around the existing scan pipeline.
//!
//! Intended for internal tooling and integration tests. Do not expose to the
//! public internet without authentication, TLS, and path allowlists.

use ares_core::AresConfig;
use ares_v3::commands::scan;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing::{error, info};

#[derive(Clone)]
struct AppState {
    config: AresConfig,
    /// When set, `program_path` must resolve under this directory.
    api_root: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct ScanRequest {
    /// Absolute or relative path to an Anchor workspace or program sources.
    program_path: String,
    #[serde(default = "default_true")]
    full_pipeline: bool,
    #[serde(default = "default_false")]
    fuzz: bool,
    #[serde(default = "default_false")]
    poc: bool,
    #[serde(default = "default_max_duration")]
    max_duration_secs: u64,
    /// Override report output directory (default: `config.output_dir`).
    output_dir: Option<String>,
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

fn default_max_duration() -> u64 {
    3600
}

#[derive(Debug, Serialize)]
struct ScanResponse {
    status: &'static str,
    program_path: String,
    output_dir: String,
    message: String,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
    version: &'static str,
}

fn load_config() -> AresConfig {
    let path = std::env::var("ARES_CONFIG").unwrap_or_else(|_| "ares.toml".into());
    let p = PathBuf::from(&path);
    if p.exists() {
        match std::fs::read_to_string(&p) {
            Ok(content) => toml::from_str(&content).unwrap_or_default(),
            Err(_) => AresConfig::default(),
        }
    } else {
        AresConfig::default()
    }
}

fn load_api_root() -> Option<PathBuf> {
    std::env::var("ARES_API_ROOT")
        .ok()
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

fn validate_program_path(root: Option<&Path>, raw: &str) -> Result<PathBuf, String> {
    let p = PathBuf::from(raw.trim());
    if p.as_os_str().is_empty() {
        return Err("program_path must not be empty".into());
    }
    let meta = std::fs::metadata(&p).map_err(|e| format!("program_path not accessible: {}", e))?;
    if !meta.is_dir() {
        return Err("program_path must be a directory".into());
    }
    let canon = p
        .canonicalize()
        .map_err(|e| format!("could not canonicalize path: {}", e))?;
    if let Some(r) = root {
        let rcanon = r.canonicalize().map_err(|e| format!("ARES_API_ROOT: {}", e))?;
        if !canon.starts_with(&rcanon) {
            return Err(format!(
                "program_path {:?} is outside ARES_API_ROOT {:?}",
                canon, rcanon
            ));
        }
    }
    Ok(canon)
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "ares-api",
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn scan_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ScanRequest>,
) -> Result<Json<ScanResponse>, (StatusCode, String)> {
    let program_path = validate_program_path(state.api_root.as_deref(), &req.program_path)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let output = req
        .output_dir
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(|| state.config.output_dir.clone());

    info!(
        "API scan requested path={:?} fuzz={} poc={}",
        program_path, req.fuzz, req.poc
    );

    scan::execute(
        program_path.as_path(),
        &state.config,
        None,
        req.full_pipeline,
        req.fuzz,
        req.poc,
        req.max_duration_secs,
        output.as_path(),
    )
    .await
    .map_err(|e| {
        error!("scan failed: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    })?;

    Ok(Json(ScanResponse {
        status: "completed",
        program_path: program_path.to_string_lossy().to_string(),
        output_dir: output.to_string_lossy().to_string(),
        message: "Scan finished; see ares-output report JSON under output_dir.".into(),
    }))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let bind = std::env::var("ARES_API_BIND").unwrap_or_else(|_| "127.0.0.1:8787".into());
    let config = load_config();
    let api_root = load_api_root();
    if let Some(ref r) = api_root {
        info!("ARES_API_ROOT enforced: {:?}", r);
    }

    let state = Arc::new(AppState { config, api_root });

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/scan", post(scan_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    info!("ares-api listening on http://{}", bind);
    axum::serve(listener, app).await?;
    Ok(())
}
