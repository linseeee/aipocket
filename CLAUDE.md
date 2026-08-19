# AIPocket

Scan for exposed AI infrastructure (FOFA + Shodan + GitHub artifact source), extract and validate leaked API key/URL pairs, check balances, and flag high-value findings.

## Architecture

Monorepo with two deployable services:

- **crates/** — Rust 2024 workspace. Axum HTTP API + Clap CLI, SQLx PostgreSQL, redis-rs, Reqwest.
- **frontend/** — React 19 + Vite + Tailwind v4 + shadcn/ui, managed by `pnpm`.

Infra: PostgreSQL 16 (persistent store), Redis 7 (cross-run dedup cache). Existing `.env`, `/data/aipocket`, PG, and Redis data remain unchanged during replacement.

## Key Directories

```
crates/
  aipocket/            # binary: Clap CLI and Axum server assembly
  aipocket-core/       # compatible Settings, domain models, URL normalization
  aipocket-db/         # SQLx repositories, idempotent schema, Redis dedup/lease
  aipocket-clients/    # FOFA, Shodan, GitHub, Tavily clients
  aipocket-discovery/  # discovery traits, source adapters, provider packs
  aipocket-prober/     # risk-gated probes, provider registry, validator
  aipocket-services/   # scanner, balance, scheduler
  aipocket-api/        # Axum routes, JWT, settings, SSE, ScanManager
frontend/              # React application
docs/
```

## Development

```bash
# Rust backend
cargo build --workspace
cargo run -p aipocket -- --help
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

# Frontend
cd frontend
pnpm install
pnpm dev                             # Vite dev server on :5173
pnpm build && pnpm preview           # production build

# Docker (dev — explicit dev compose file, not auto-loaded)
docker compose -f docker-compose.yml -f docker-compose.dev.yml up

# Docker (prod — compose file only; no dev overrides)
docker compose -f docker-compose.yml up -d
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `aipocket scan` | Run a full scan (FOFA + Shodan + optional GitHub + extract + validate + balance). Opt-in resume: `--resume-run run_YYYY_...` (requires PostgreSQL spill tables) |
| `aipocket serve` | Start the Axum web API |
| `aipocket watch` | Periodic scanner (scheduler loop) |
| `aipocket queries` | Print current FOFA/Shodan query sets |
| `aipocket config` | Show resolved config |
| `aipocket shodan-info` | Show Shodan account info |
| `aipocket cve-sync` | Sync CVE data from Tavily |
| `aipocket balance` | Re-check balances for stored keys |

## Code Conventions

- Backend formatter/linter: `cargo fmt --all` and `cargo clippy --workspace --all-targets -- -D warnings`.
- Frontend linter: `oxlint`. Run `pnpm lint`.
- Tests use Rust unit/integration tests; PostgreSQL/Redis compatibility cases run through ignored tests in CI.
- Config and DTOs use Serde; SQL uses SQLx.
- All async I/O uses Tokio and a shared `reqwest::Client`.
- Frontend uses `@tanstack/react-query` for server state, `react-router-dom` v6 for routing.

## Environment

All config via `.env` (see `.env.example`). Key variables:
- `FOFA_KEYS`, `SHODAN_KEYS` — comma-separated API key lists
- `DATABASE_URL` — PostgreSQL connection string
- `DEDUP_REDIS_URL` — Redis for dedup
- `GPT_BASE_URL`, `GPT_KEY`, `GPT_MODEL` — LLM for analysis
- `WEB_PASSWORD`, `WEB_JWT_SECRET` — web UI auth

## Rules

- Never commit `.env` or real API keys. Use `.env.example` for documentation.
- Prefer small, reviewable changes with clear verification steps.
- Run `cargo test --workspace` and the PostgreSQL/Redis ignored integration tests before submitting backend changes.
- Run `pnpm build` to verify frontend compiles before submitting.
