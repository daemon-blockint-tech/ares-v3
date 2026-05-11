# API development for ARES

This directory documents how to expose and evolve **HTTP APIs** around the ARES V3 Solana security scanner. The reference implementation lives in the workspace crate [`crates/ares-api`](../crates/ares-api).

## Goals

- **Thin controllers**: HTTP handlers validate input, call existing `ares-v3` commands (`scan::execute`), and return structured JSON.
- **Explicit types**: Request/response bodies are serde models; errors map to HTTP status codes with clear messages.
- **Safe defaults**: Bind to loopback only, optional path jail via `ARES_API_ROOT`, no authentication in the MVP (add reverse-proxy + API keys before any public exposure).

## Reference server (`ares-api`)

| Endpoint        | Method | Purpose                          |
|-----------------|--------|----------------------------------|
| `/health`       | GET    | Liveness / version               |
| `/v1/scan`      | POST   | Run the same pipeline as `ares scan` |

### Environment

| Variable          | Default              | Description                                      |
|-------------------|----------------------|--------------------------------------------------|
| `ARES_API_BIND`   | `127.0.0.1:8787`     | Socket to listen on                              |
| `ARES_CONFIG`     | `ares.toml`          | Path to ARES config (same as CLI)                |
| `ARES_API_ROOT`   | _(unset)_            | If set, `program_path` must stay under this root |
| `RUST_LOG`        | _(none)_             | e.g. `info,ares_api=debug` for tracing           |

### Run

From the repository root:

```bash
cargo run -p ares-api
```

Example scan (another terminal):

```bash
curl -sS -X POST http://127.0.0.1:8787/v1/scan \
  -H 'Content-Type: application/json' \
  -d '{"program_path":"/absolute/path/to/anchor-workspace","fuzz":false,"poc":false}'
```

### Machine-readable contract

See [`openapi.yaml`](./openapi.yaml) for a minimal OpenAPI 3.1 description of the MVP routes.

## Extension checklist

When you grow this API (NestJS/Go gateways can proxy to `ares-api` or reimplement contracts):

1. **Authentication** — API keys or mTLS at the edge; do not ship long-lived secrets in repo config.
2. **Rate limiting** — Per client/IP at reverse proxy or with `tower::limit`.
3. **Async jobs** — Long scans should return `202` + `job_id` and poll `/v1/jobs/{id}`; the current handler runs synchronously.
4. **Webhooks / callbacks** — Optional notify URL with signed payloads after scan completion.
5. **Input bounds** — Cap `max_duration_secs`, reject path traversal (`..`), keep `ARES_API_ROOT` mandatory in multi-tenant deployments.

## Related code

- [`crates/ares-api`](../crates/ares-api) — Axum binary
- [`crates/ares-cli/src/commands/scan.rs`](../crates/ares-cli/src/commands/scan.rs) — Core scan implementation
- [`crates/ares-core`](../crates/ares-core) — `AresConfig`, report types
