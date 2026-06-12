# CEEM

Continuous External Exposure Monitor.

CEEM is a learning-first, portfolio-grade Rust project inspired by the practical systems style of *Zero to Production* and the security-builder mindset of *Black Hat Rust*. The product goal is a safe external exposure cockpit for startups: register authorized domains, run low-risk continuous checks, store findings, alert teams in Slack, and track remediation work.

## Current Scope

This repository is intentionally starting with guardrails before power:

- Domain-only assets for the MVP.
- Explicit authorization attestation before scans.
- Passive and low-impact active checks first.
- Authenticated organizations and teams from day one.
- Slack alerts first, then email/webhook/issue tracker integrations later.
- Cloud deployment planned early, but local development stays simple.

## Workspace

```text
crates/api       Axum HTTP API
crates/worker    Background scanning and alert worker
crates/scanner   Domain scanner guardrails and scan orchestration
crates/findings  Finding rules, normalization, lifecycle helpers
crates/alerts    Slack alert formatting and delivery models
crates/auth      Auth policy and later session/password implementation
crates/db        Database config and persistence layer
crates/shared    Shared domain models and validation
web/             React + TypeScript dashboard
migrations/      PostgreSQL schema migrations
docs/            ART planning, architecture, and security model
```

## Local Development

Prerequisites:

- Rust 1.93+
- Node.js 24+
- Docker Desktop

Start Postgres:

```powershell
docker compose up -d postgres
```

Run the API:

```powershell
Copy-Item .env.example .env
cargo run -p ceem-api
```

Check health:

```powershell
Invoke-RestMethod http://127.0.0.1:8080/healthz
```

Run tests:

```powershell
cargo test --workspace
```

Run the dashboard:

```powershell
cd web
npm install
npm run dev
```

## Safety Position

CEEM is not an exploitation framework. MVP checks are designed to identify externally visible risk indicators without bypassing controls, authenticating to third-party systems, exploiting vulnerabilities, or scanning assets the user has not attested they are authorized to monitor.

See [Security Model](docs/security-model.md).
