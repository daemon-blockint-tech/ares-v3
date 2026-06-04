pub mod commands;
pub mod fork_validator;
pub mod poc;
pub mod validator;
pub mod scorer;
pub mod llm_judge;
pub mod tui;

/// Re-export SDK crates for unified access
pub use ares_orchestrator as agent;
pub use ares_report;

/// Report format options for export.
#[derive(clap::ValueEnum, Clone, Debug)]
pub enum ReportFormat {
    Markdown,
    Pdf,
    Json,
    Html,
    GithubIssue,
}
