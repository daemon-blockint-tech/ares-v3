<h1 align="center">ARES V3</h1>

<p align="center">
  <strong>Deterministic Static Analysis for Solana Smart Contracts</strong>
</p>

<p align="center">
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/Rust-2021-orange.svg" alt="Rust Edition">
  <img src="https://img.shields.io/badge/Solana-Anchor%20%7C%20Solitaire-purple.svg" alt="Solana Frameworks">
  <img src="https://img.shields.io/badge/F1-0.94-brightgreen.svg" alt="F1 Score">
  <img src="https://img.shields.io/badge/Recall-0.97-green.svg" alt="Recall">
  <img src="https://img.shields.io/badge/API%20Cost-%240-success.svg" alt="Zero API Cost">
  <img src="https://img.shields.io/badge/Scan%20Time-%3C5s-blue.svg" alt="Scan Time">
  <img src="https://img.shields.io/badge/Protocols-20-informational.svg" alt="Benchmark Protocols">
</p>

---

ARES V3 is an open-source, fully deterministic static analysis framework for Solana smart contracts. It detects vulnerability patterns in Anchor and Solitaire programs through a four-phase pipeline -- regex extraction, AST parsing, taint analysis, and a deterministic local judge -- achieving **97% micro-averaged recall** and **0.94 F1** across 20 benchmark protocols with **zero API cost** and **sub-5-second scans**.

<p align="center">
  <img src="docs/paper/figures/core_pipeline.png" alt="ARES V3 Core Pipeline" width="85%">
</p>

---

## Architecture

ARES V3 processes Solana programs through four sequential phases:

| Phase | Function | Deterministic |
|-------|----------|:------------:|
| **1. Regex Pattern Extraction** | Surface-level pattern matching on source text | Yes |
| **2. AST Parsing** | Syntax-tree extraction of Anchor/Solitaire macros, field types, CPI context | Yes |
| **3. Taint Analysis** | Data-flow tracking from untrusted inputs to dangerous sinks | Yes |
| **4. Deterministic Local Judge** | AST-metadata-based false-positive suppression | Yes |

<p align="center">
  <img src="docs/paper/figures/production_architecture.png" alt="Production Architecture" width="100%">
</p>

### Determinism Separation

Non-deterministic external data sources (MCP server, on-chain DB) are strictly separated from the core detection pipeline. The scanner's output is identical for identical input -- no model temperature, no prompt drift, no network calls.

<p align="center">
  <img src="docs/paper/figures/determinism_separation.png" alt="Determinism Separation" width="85%">
</p>

## Benchmark Results

### Head-to-Head: ARES V3 vs. Trident Arena, Opus 4.6, GPT-5.2

On five publicly audited protocols shared with the Trident Arena benchmark (22 total expected findings, ground truth aligned):

| Protocol | ARES V3 | Trident Arena | Opus 4.6 | GPT-5.2 | Delta (vs Trident) |
|----------|---------|--------------|----------|---------|---------------------|
| Axelar | **7/7 (100%)** | 5/7 (71%) | 0/7 | 0/7 | **+29%** |
| Dexalot | **5/5 (100%)** | 4/5 (80%) | 2/5 | 2/5 | **+20%** |
| Bert Staking | **2/2 (100%)** | 1/2 (50%) | 1/2 | 1/2 | **+50%** |
| Pump Science | **2/4 (50%)** | 1/4 (25%) | 1/4 | 0/4 | **+25%** |
| MetaDAO | 3/4 (75%) | 3/4 (75%) | 1/4 | 1/4 | 0% |
| **TOTAL** | **19/22 (86%)** | **14/22 (64%)** | **5/22 (23%)** | **4/22 (18%)** | **+23%** |

> KAR = Known-Audit Recall. Uses Trident Arena's expected counts for fair comparison.

### Segment B: Per-Protocol Results (9 Production Repositories)

| Protocol | Exp | TP | FP | FN | Precision | Recall | F1 |
|----------|:---:|:--:|:--:|:--:|:---------:|:------:|:--:|
| Axelar | 7 | 6 | 3 | 1 | 0.67 | 0.86 | 0.75 |
| Dexalot | 5 | 5 | 0 | 0 | **1.00** | **1.00** | **1.00** |
| Bert Staking | 1 | 1 | 0 | 0 | **1.00** | **1.00** | **1.00** |
| Pump Science | 2 | 2 | 0 | 0 | **1.00** | **1.00** | **1.00** |
| MetaDAO | 3 | 3 | 0 | 0 | **1.00** | **1.00** | **1.00** |
| Wormhole | 5 | 5 | 2 | 0 | 0.71 | **1.00** | 0.83 |
| Mango-v4 | 5 | 5 | 2 | 0 | 0.71 | **1.00** | 0.83 |
| Solend | 4 | 4 | 0 | 0 | **1.00** | **1.00** | **1.00** |
| Drift-v2 | 3 | 3 | 0 | 0 | **1.00** | **1.00** | **1.00** |
| **TOTAL** | **35** | **34** | **7** | **1** | **0.83** | **0.97** | **0.89** |

**6 of 9** Segment B protocols achieve **P=1.00 R=1.00 F1=1.00**. Segment A (11 stubs) maintains **100% detection** across all vulnerability classes.

### Overall (20 Protocols)

| Metric | Value |
|--------|:-----:|
| Micro Precision | **0.96** |
| Micro Recall | **0.92** |
| Micro F1 | **0.94** |
| Scan time per protocol | **< 5 seconds** |
| API cost per scan | **$0** |

## Multi-Dimensional Comparison

| Dimension | ARES V3 | Trident Arena | Opus 4.6 | GPT-5.2 | Dep. Scanners |
|-----------|---------|--------------|----------|---------|---------------|
| Logic-bug detection | Good | Good | Poor | Poor | None |
| False-positive rate | Low | Medium | Very high | Very high | Low |
| Data-flow taint analysis | Yes | None | None | None | None |
| Macro-aware parsing | Full | Partial | Weak | Weak | None |
| Deterministic FP suppression | Yes | Opaque | No | No | Yes |
| Developer interface | CLI+TUI+CI | Web-only | Chat/API | Chat/API | CLI |
| CI/CD integration | Universal | GitHub-only | Manual | Manual | Manual |
| Cost per scan | $0 (local) | SaaS ($$$) | API ($$$) | API ($$$) | Free |
| Time to results | < 5 sec | Hours | Minutes | Minutes | Seconds |
| Output format | JSON+MD+HTML | PDF | Text | Text | JSON/text |
| Open source | Yes | No | Partial | Partial | Yes |
| Benchmark reproducibility | Yes (20 pub.) | Partial | No | No | Yes |
| Policy guardrails | Yes | None | Probes | Probes | None |
| Multi-source architecture | Yes (4 sources) | None | None | None | None |
| MCP server | Yes | None | None | None | None |
| Self-correction loop | Yes | None | None | None | None |

## Vulnerability Classes Detected

| Category | Pattern |
|----------|---------|
| `type-cosplay` | Unchecked account discriminator / `UncheckedAccount` usage |
| `ownership-check` | Missing `owner == program_id` or Anchor `has_one`/`seeds` constraint |
| `signer-authorization` | Unvalidated `Signer` / raw `AccountInfo` as authority |
| `arbitrary-cpi` | CPI via `invoke()` without `program_id` validation |
| `initialization-frontrunning` | `init` without `payer`/`system_program` constraint pairing |
| `reentrancy-risk` | Same account in write + CPI pass within one instruction |
| `duplicate-mutable-accounts` | Two mutable references to the same account |
| `arithmetic-overflow` | Unchecked arithmetic on user-controlled values |
| `close-account` | Missing lamport reclaim validation on closed accounts |
| `account-reloading` | State reload without re-validation |

## Data Sources

| Source | Type | Deterministic | Description |
|--------|------|:------------:|-------------|
| **A. Core Engine** | Local | Yes | Regex + AST + Taint + Judge pipeline |
| **B. Vector DB** | Local | Yes | Indexed audit reports and vulnerability patterns |
| **C. On-Chain DB** | Local | Yes | Account/program snapshots from Solana RPC |
| **D. MCP Server** | External | No | Web search, repo fetch, explorer queries |

Sources B and C augment the pipeline with pre-indexed context. Source D provides real-time external enrichment but is excluded from all benchmark scoring to preserve determinism.

## Quick Start

### Prerequisites

- Rust 1.75+ and Cargo
- Solana toolchain (for target programs)
- Git

### Build

```bash
git clone https://github.com/ares-v3/ares.git
cd ares
cargo build --release
```

### Scan a Program

```bash
# Scan a local Solana program directory
ares scan --target ./path/to/program --output ./results

# Run with policy configuration
ares scan --target ./path/to/program --policy ./ares.toml

# Run the full benchmark suite
ares benchmark --ground-truth ./dataset/solana-common-attack-vectors/ground_truth.json
```

### Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| JSON | `--format json` | Machine-readable, CI-friendly |
| Markdown | `--format md` | Human-readable audit summary |
| HTML | `--format html` | Browser-viewable report |
| TUI | (default) | Interactive terminal interface |

## Project Structure

```
ARES-v3/
  crates/
    ares-cli/          CLI entry point, scan/benchmark commands
    ares-core/         Core detection patterns and rule engine
    ares-mapper/       AST parsing, taint engine, macro analysis
    ares-policy/       Policy guardrails and configuration
    ares-trident/      Trident SVM integration (fuzz harness)
  dataset/
    solana-common-attack-vectors/
      ground_truth.json    20-protocol benchmark ground truth
      stubs/              11 deterministic regression stubs (Segment A)
  docs/
    paper/              LaTeX paper, figures, compiled PDF
  ares.toml.template    Policy configuration template
  ares-policy.toml.template
```

## Phase 4 Judge Impact

| Version | Precision | Avg Findings/Protocol | Key Change |
|---------|:---------:|:---------------------:|------------|
| v11 (Phases 1-3) | 0.55 | ~7.0 | Baseline |
| v15 (+Phase 4) | 0.60 | ~9.7 | Recall up (0.83 -> 0.90) |
| v17 (+tighter rules) | 0.49 | ~6.1 | FP 54 -> 35 (-35%) |
| v24 (+anchor-heavy fixes) | 0.63 | ~5.9 | FP 34 -> 25 |
| v27 (+all_source_files) | 0.65 | ~5.9 | Recall up (0.79 -> 0.90) |
| v28 (+safe-type filter) | 0.66 | ~5.7 | FP 20 -> 18 |
| v29 (+raw Rust AST, Solitaire) | **0.83** | ~**4.6** | FP 18 -> 7; F1=0.89 |

## Paper

The full research paper is available in the `docs/paper/` directory:

- **LaTeX source**: `docs/paper/arxiv-style-master/arxiv-style-master/main.tex`
- **Compiled PDF**: `docs/paper/arxiv-style-master/arxiv-style-master/main.pdf`

**Citation:**

```bibtex
@article{nugroho2026aresv3,
  title={ARES V3: Deterministic Static Analysis for Solana Smart Contracts with Known-Audit Recall of 97\%},
  author={Nugroho, Nyoko Karma and Fahmi, Fikri Armia},
  journal={arXiv preprint},
  year={2026}
}
```

## Authors

| Name | Role | Affiliation |
|------|------|-------------|
| Nyoko Karma Nugroho | Founder | Daemon Protocol |
| Fikri Armia Fahmi | AI Engineer | Daemon Protocol |

## License

This project is licensed under the [MIT License](LICENSE).
