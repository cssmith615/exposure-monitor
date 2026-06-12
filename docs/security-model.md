# CEEM Security Model

## Product Boundary

CEEM monitors assets the user declares they are authorized to monitor. It is not designed to exploit systems, bypass controls, harvest credentials, or automate restricted platforms.

## Human Approval and Authorization

Before a domain becomes scannable, the user must attest authorization. This is stored with:

- User ID.
- Organization ID.
- Domain.
- Timestamp.

Future higher-risk actions should add stronger verification, such as DNS TXT validation.

## MVP Scanner Constraints

Allowed:

- DNS lookup.
- HTTP/HTTPS metadata collection.
- TLS certificate inspection.
- Security header checks.
- Low-volume scheduled rechecks.

Disallowed:

- Login attempts.
- Password or token testing.
- Exploit payloads.
- Forced browsing beyond minimal metadata checks.
- CAPTCHA bypass.
- Scanning LinkedIn, Indeed, or restricted platforms.
- IP scanning until explicitly designed and rate-limited.

## Multitenancy

Rules:

- All tenant data must be scoped by organization.
- Users can only access organizations where they are members.
- Write operations require role checks.
- Audit logs must capture material actions.

Initial roles:

- `owner`: full control, billing-ready owner role later.
- `admin`: manage assets, scans, alerts, and members except owner controls.
- `member`: view and manage findings/remediation.
- `viewer`: read-only dashboard access.

## Secrets

Secrets must not be stored in `.env.example`, docs, tests, or seed data.

Slack webhook storage plan:

- Local development can use environment variables.
- Cloud deployments should use a secret manager.
- Database stores secret references, not plaintext webhooks, once secret management is added.

## Audit Events

Audit at minimum:

- User registration.
- Login failures after threshold.
- Organization creation.
- Member invitation and role changes.
- Domain creation, deletion, and authorization attestation.
- Scan trigger.
- Finding status change.
- Slack channel creation/update.
- Alert delivery failure.

## Abuse Prevention

MVP controls:

- Domain-only input.
- Domain validation rejects URLs and paths.
- Authorization attestation required.
- Conservative scanner behavior.

Planned controls:

- Per-organization scan quotas.
- Per-domain rate limits.
- DNS ownership verification.
- Worker concurrency limits.
- Scan intensity policy.
- Abuse-report contact in public docs.
