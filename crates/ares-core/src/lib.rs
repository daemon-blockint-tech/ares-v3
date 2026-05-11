use std::fmt;
use std::path::PathBuf;
use thiserror::Error;

/// Global result type for ARES operations.
pub type AresResult<T> = Result<T, AresError>;

/// Global error type for ARES operations.
#[derive(Error, Debug)]
pub enum AresError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Config error: {0}")]
    Config(String),

    #[error("Trident integration error: {0}")]
    Trident(String),

    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Execution failed: {0}")]
    Execution(String),

    #[error("Benchmark error: {0}")]
    Benchmark(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("External tool missing: {0}")]
    ToolMissing(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Severity level of a vulnerability finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "Critical"),
            Severity::High => write!(f, "High"),
            Severity::Medium => write!(f, "Medium"),
            Severity::Low => write!(f, "Low"),
            Severity::Informational => write!(f, "Informational"),
        }
    }
}

/// Represents a single vulnerability finding.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub category: String,
    pub location: CodeLocation,
    pub proof_of_concept: Option<PathBuf>,
    pub recommendation: String,
    pub references: Vec<String>,
    pub confidence: f64, // 0.0 - 1.0
}

/// Represents a suppressed finding.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SuppressedFinding {
    pub finding: Finding,
    pub reason: String,
    pub suppressed_by: String, // "local_judge" or "llm_judge"
}

/// Code location reference.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CodeLocation {
    pub file: PathBuf,
    pub line_start: Option<u32>,
    pub line_end: Option<u32>,
    pub column_start: Option<u32>,
    pub column_end: Option<u32>,
    pub function: Option<String>,
    pub commit: Option<String>,
}

/// A complete audit report for a Solana program.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditReport {
    pub target: ProgramTarget,
    pub findings: Vec<Finding>,
    pub suppressed_findings: Vec<SuppressedFinding>,
    pub metadata: ReportMetadata,
    pub summary: ReportSummary,
}

/// Target program specification.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProgramTarget {
    pub name: String,
    pub repository_url: Option<String>,
    pub commit_hash: Option<String>,
    pub program_id: Option<String>,
    pub source_path: PathBuf,
    pub idl_path: Option<PathBuf>,
}

/// Metadata for an audit report.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReportMetadata {
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub ares_version: String,
    pub scan_duration_secs: u64,
    pub agent_pipeline: Vec<String>,
    pub tools_used: Vec<String>,
}

/// Summary statistics for an audit report.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ReportSummary {
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub informational_count: usize,
    pub false_positives_suppressed: usize,
    pub poc_generated: usize,
    pub tests_passed: usize,
    pub tests_failed: usize,
    /// Phase 4: Estimated total economic impact (lamports) across all findings.
    pub total_economic_impact_lamports: u64,
    /// Phase 4: Maximum extractable value from a single finding (lamports).
    pub max_single_exploit_lamports: u64,
}

/// Benchmark result for a single protocol.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BenchmarkResult {
    pub protocol_name: String,
    pub source: String,
    pub total_critical_high: usize,
    pub detected_critical_high: usize,
    pub false_positives: usize,
    pub false_negatives: usize,
    /// Renamed to known_audit_recall for honesty. Was `detection_rate`.
    /// This is TP / Expected — how many *known audit findings* we recalled.
    /// It is NOT "all vulnerabilities in the codebase".
    #[serde(rename = "detection_rate")]
    pub known_audit_recall: f64,
    pub fp_rate: f64,
    pub poc_success_rate: f64,
    pub execution_time_secs: u64,
    /// Phase 4: Estimated maximum extractable economic value (lamports).
    pub economic_score_lamports: u64,
    /// Phase 6: Precision = TP / (TP + FP). Real-world: often 40-70%.
    pub precision: f64,
    /// Phase 6: Recall = TP / (TP + FN) — same as known_audit_recall.
    pub recall: f64,
    /// Phase 6: F1 Score = 2 * (precision * recall) / (precision + recall).
    pub f1_score: f64,
    /// Phase 9: Which categories were actually detected by the analyzer.
    pub detected_categories: Vec<String>,
    /// Phase 10: Total unique categories flagged by the analyzer (TP + FP).
    /// Represents findings that require human triage.
    pub total_findings: usize,
}

/// LLM provider selection for ARES-as-Judge.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LlmProvider {
    Openai,
    Anthropic,
    Ollama,
    Disabled,
}

impl Default for LlmProvider {
    fn default() -> Self {
        LlmProvider::Disabled
    }
}

/// Configuration for ARES CLI.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct AresConfig {
    pub trident_path: Option<PathBuf>,
    pub solana_cli_path: Option<PathBuf>,
    pub anchor_cli_path: Option<PathBuf>,
    pub output_dir: PathBuf,
    pub sandbox_image: String,
    pub max_fuzz_iterations: u64,
    pub max_scan_duration_secs: u64,
    pub llm_model: String,
    pub llm_provider: LlmProvider,
    pub llm_api_key: Option<String>,
    pub llm_base_url: Option<String>,
    pub llm_judge_enabled: bool,
    /// Extended deterministic heuristics for the Local Judge
    pub judge_extended: bool,
    /// Max LLM tokens per API call (budget throttle).
    pub llm_max_tokens_per_call: u32,
    /// Max findings sent to LLM per scan (prioritizes high-confidence).
    pub llm_max_findings_per_scan: usize,
    pub policy_file: Option<PathBuf>,
    pub benchmark_dataset_path: Option<PathBuf>,
    /// Enable mainnet fork simulation in PoC validation.
    pub mainnet_fork_enabled: bool,
    /// Specific slot to fork from (None = latest).
    pub mainnet_fork_slot: Option<u64>,
    /// RPC URL to fork mainnet state from (default: https://api.mainnet-beta.solana.com).
    pub mainnet_rpc_url: Option<String>,
    /// Accounts to `--clone` into the local validator (program IDs, token accounts, PDAs).
    pub mainnet_clone_accounts: Vec<String>,
}

impl Default for AresConfig {
    fn default() -> Self {
        Self {
            trident_path: None,
            solana_cli_path: None,
            anchor_cli_path: None,
            output_dir: PathBuf::from("./ares-output"),
            sandbox_image: "ares-v3/sandbox:latest".to_string(),
            max_fuzz_iterations: 100_000,
            max_scan_duration_secs: 3600,
            llm_model: "claude-3-5-sonnet".to_string(),
            llm_provider: LlmProvider::Disabled,
            llm_api_key: None,
            llm_base_url: None,
            llm_judge_enabled: false,
            judge_extended: false,
            llm_max_tokens_per_call: 2048,
            llm_max_findings_per_scan: 20,
            policy_file: Some(PathBuf::from("ares-policy.toml")),
            benchmark_dataset_path: Some(PathBuf::from("./dataset")),
            mainnet_fork_enabled: false,
            mainnet_fork_slot: None,
            mainnet_rpc_url: Some("https://api.mainnet-beta.solana.com".to_string()),
            mainnet_clone_accounts: Vec::new(),
        }
    }
}
