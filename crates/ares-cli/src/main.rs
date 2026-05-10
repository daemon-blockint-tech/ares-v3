use anyhow::Result;
use ares_core::AresConfig;
use ares_cli::ReportFormat;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::{info, warn};

/// ARES V3 — Autonomous Solana Security Auditor
/// Designed to exceed Trident Arena benchmarks across every dimension.
#[derive(Parser, Debug)]
#[command(name = "ares", about, version, long_about = None)]
struct Cli {
    /// Path to ARES configuration file
    #[arg(short, long, value_name = "FILE", default_value = "ares.toml")]
    config: PathBuf,

    /// Enable verbose logging
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Policy override: require explicit approval for dangerous operations
    #[arg(long, default_value = "true")]
    strict_policy: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize ARES workspace and verify dependencies
    Init {
        /// Project directory to initialize
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Run a security scan on a Solana program
    Scan {
        /// Path to the Solana program (Anchor project directory)
        #[arg(value_name = "PATH")]
        program_path: PathBuf,

        /// Scan only specific file or module
        #[arg(short, long)]
        target: Option<String>,

        /// Enable full multi-agent pipeline (Mapper -> Hypothesis -> Fuzzer -> Exploit -> Triager -> Reporter)
        #[arg(long, default_value = "true")]
        full_pipeline: bool,

        /// Run property-based fuzzing with Trident
        #[arg(long, default_value = "true")]
        fuzz: bool,

        /// Generate deterministic proof-of-concept tests for each finding
        #[arg(long, default_value = "true")]
        poc: bool,

        /// Maximum scan duration in seconds
        #[arg(long, default_value = "3600")]
        max_duration: u64,

        /// Output directory for reports and artifacts
        #[arg(short, long, default_value = "./ares-output")]
        output: PathBuf,
    },

    /// Run fuzzing campaign with Trident
    Fuzz {
        /// Path to the fuzz test or program
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Number of fuzz iterations
        #[arg(short, long, default_value = "100000")]
        iterations: u64,

        /// Specific fuzz test name to run
        #[arg(short, long)]
        test: Option<String>,

        /// Run in deterministic mode with fixed seed
        #[arg(long)]
        deterministic: bool,
    },

    /// Run benchmark suite against known protocols
    Benchmark {
        /// Benchmark dataset path
        #[arg(short, long, default_value = "./dataset")]
        dataset: PathBuf,

        /// Specific protocol to benchmark (e.g., axelar, dexalot, watt)
        #[arg(short, long)]
        protocol: Option<String>,

        /// Compare results against Trident Arena baseline
        #[arg(long, default_value = "true")]
        compare_baseline: bool,

        /// Generate benchmark report
        #[arg(short, long, default_value = "./ares-benchmark-report.json")]
        output: PathBuf,
    },

    /// Validate a proof-of-concept in sandboxed environment
    Validate {
        /// Path to PoC test or exploit script
        #[arg(value_name = "PATH")]
        poc_path: PathBuf,

        /// Fork mainnet state for realistic conditions
        #[arg(long)]
        fork_mainnet: bool,

        /// Specific slot to fork from
        #[arg(long)]
        fork_slot: Option<u64>,

        /// Override mainnet RPC URL for fork (e.g. Helius, QuickNode)
        #[arg(long)]
        rpc_url: Option<String>,
    },

    /// Report generation and export
    Report {
        /// Scan output directory to generate report from
        #[arg(value_name = "DIR")]
        scan_output: PathBuf,

        /// Report format
        #[arg(short, long, value_enum, default_value = "markdown")]
        format: ReportFormat,

        /// Output file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Check system dependencies and policy status
    Doctor {},

    /// Manage policy and capability escalation
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },

    /// Generate self-contained HTML benchmark dashboard
    Dashboard {
        /// Path to benchmark JSON output
        #[arg(value_name = "FILE")]
        benchmark_json: PathBuf,

        /// Output file path
        #[arg(short, long, default_value = "./ares-dashboard.html")]
        output: PathBuf,

        /// Output format (html or pdf)
        #[arg(short, long, value_enum, default_value = "html")]
        format: ReportFormat,
    },
}

#[derive(Subcommand, Debug)]
enum PolicyCommands {
    /// Show current policy status
    Status,
    /// Request capability escalation
    Escalate { capability: String },
    /// Reset policy to default
    Reset,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let log_level = match cli.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(format!("ares={}", log_level))
        .init();

    info!("ARES V3 — Autonomous Solana Security Auditor");
    info!("Phase 1: Trident Integration + Multi-Agent Pipeline");

    // Load or initialize config
    let config = if cli.config.exists() {
        load_config(&cli.config)?
    } else {
        warn!("Config file not found at {:?}, using defaults", cli.config);
        AresConfig::default()
    };

    // Route commands
    match cli.command {
        Commands::Init { path } => {
            info!("Initializing ARES workspace at {:?}", path);
            ares_cli::commands::init::execute(&path).await?;
        }
        Commands::Scan {
            program_path,
            target,
            full_pipeline,
            fuzz,
            poc,
            max_duration,
            output,
        } => {
            info!(
                "Scanning {:?} | pipeline={} fuzz={} poc={} duration={}s",
                program_path, full_pipeline, fuzz, poc, max_duration
            );
            ares_cli::commands::scan::execute(
                &program_path,
                &config,
                target,
                full_pipeline,
                fuzz,
                poc,
                max_duration,
                &output,
            )
            .await?;
        }
        Commands::Fuzz {
            path,
            iterations,
            test,
            deterministic,
        } => {
            info!(
                "Running fuzz campaign on {:?} | iterations={} deterministic={}",
                path, iterations, deterministic
            );
            ares_cli::commands::fuzz::execute(&path, iterations, test, deterministic).await?;
        }
        Commands::Benchmark {
            dataset,
            protocol,
            compare_baseline,
            output,
        } => {
            info!(
                "Running benchmark | dataset={:?} protocol={:?} compare={}",
                dataset, protocol, compare_baseline
            );
            ares_cli::commands::benchmark::execute(&dataset, protocol, compare_baseline, &output)
                .await?;
        }
        Commands::Validate {
            poc_path,
            fork_mainnet,
            fork_slot,
            rpc_url,
        } => {
            info!(
                "Validating PoC {:?} | fork_mainnet={} slot={:?} rpc={:?}",
                poc_path, fork_mainnet, fork_slot, rpc_url
            );
            ares_cli::commands::validate::execute(&poc_path, fork_mainnet, fork_slot, &config, rpc_url).await?;
        }
        Commands::Report {
            scan_output,
            format,
            output,
        } => {
            info!(
                "Generating report from {:?} | format={:?}",
                scan_output, format
            );
            ares_cli::commands::report::execute(&scan_output, format, output).await?;
        }
        Commands::Doctor {} => {
            ares_cli::commands::doctor::execute().await?;
        }
        Commands::Policy { command } => match command {
            PolicyCommands::Status => {
                ares_cli::commands::policy::status().await?;
            }
            PolicyCommands::Escalate { capability } => {
                ares_cli::commands::policy::escalate(&capability).await?;
            }
            PolicyCommands::Reset => {
                ares_cli::commands::policy::reset().await?;
            }
        },
        Commands::Dashboard {
            benchmark_json,
            output,
            format,
        } => {
            info!(
                "Generating dashboard from {:?} -> {:?} (format: {:?})",
                benchmark_json, output, format
            );
            ares_cli::commands::dashboard::execute(&benchmark_json, &output, format).await?;
        }
    }

    info!("ARES command completed successfully.");
    Ok(())
}

fn load_config(path: &PathBuf) -> Result<AresConfig> {
    let content = std::fs::read_to_string(path)?;
    let config: AresConfig = toml::from_str(&content)?;
    Ok(config)
}
