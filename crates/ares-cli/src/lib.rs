pub mod commands;
pub mod fork_validator;
pub mod poc;
pub mod validator;
pub mod scorer;
pub mod llm_judge;

/// Report format options for export.
#[derive(clap::ValueEnum, Clone, Debug)]
pub enum ReportFormat {
    Markdown,
    Pdf,
    Json,
    Html,
    GithubIssue,
}
