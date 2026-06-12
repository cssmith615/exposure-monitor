# CEEM Deployment Guide

## Services

CEEM deploys as four runtime units:

- `ceem-api`: Axum API, auth boundary, migrations, organization-scoped CRUD.
- `ceem-worker`: long-running scanner worker that claims queued jobs from Postgres.
- `web`: static React dashboard.
- `postgres`: local development database, replaced by managed Postgres in cloud.

## Required Environment

- `DATABASE_URL`: Postgres connection string with TLS in production.
- `CEEM_SESSION_SECRET`: high-entropy secret for JWT signing.
- `CEEM_BIND_ADDR`: API bind address, normally `0.0.0.0:8080` in containers.
- `CEEM_WORKER_POLL_SECONDS`: worker idle poll interval.
- `VITE_CEEM_API_URL`: public browser URL for the API, baked into the web build.
- `RUST_LOG`: structured JSON log level, for example `info,ceem_api=debug`.

Never commit production `.env` files. Store `DATABASE_URL`, Slack webhooks, and session keys in the cloud provider secret manager.

## Local Container Run

```powershell
docker compose up --build
```

Then open:

- Dashboard: `http://127.0.0.1:5317`
- API health: `http://127.0.0.1:8080/healthz`

The API runs migrations at startup through `ceem-db`.

## Cloud Shape

1. Create managed Postgres.
2. Create container registry.
3. Build and push `crates/api/Dockerfile`, `crates/worker/Dockerfile`, and `web/Dockerfile`.
4. Deploy API as an HTTPS service with `DATABASE_URL` and `CEEM_SESSION_SECRET`.
5. Deploy worker as a private background service with the same `DATABASE_URL`.
6. Deploy web as static container or static hosting with `VITE_CEEM_API_URL` set to the public API origin.
7. Restrict database ingress to API and worker runtimes.
8. Configure log retention and alerts for worker failures, API 5xx rate, and queue depth.

## Production Notes

- Use a non-default `CEEM_SESSION_SECRET` before creating users.
- Prefer managed Postgres backups and point-in-time recovery.
- Rotate Slack webhook URLs by creating a new notification channel, validating alert delivery, then disabling the old channel.
- Run one or more worker replicas. Job claiming uses `FOR UPDATE SKIP LOCKED`, so multiple workers can safely share the queue.
- Start with low worker concurrency and conservative scan schedules. CEEM must remain a low-impact monitor, not a stress tester.
