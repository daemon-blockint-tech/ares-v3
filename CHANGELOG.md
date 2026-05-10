# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Open-source release preparation.
- Extended deterministic local judge rules (v29 heuristics).
- Structured terminal output with severity-colored findings.
- `.github` templates and CI/CD workflows.
- MCP Server crate for external tool enrichment.
- Git LFS support for benchmark dataset.

## [0.1.0] - 2026-05-10
### Added
- Initial implementation of the 4-phase deterministic static analysis pipeline.
- `ares-mapper` with AST parsing (`syn` + `proc-macro2`) and intra-procedural taint tracking.
- `ares-policy` engine with IronCurtain-style sandbox boundaries.
- `ares-trident` integration for SVM-based fuzzing and PoC execution.
- Economic exploit scorer (SCONE-bench inspired).
- Benchmarking system with 11 stubs (Segment A) and 9 production repos (Segment B).
- LLM-as-Judge validation support (optional, requires API key).
