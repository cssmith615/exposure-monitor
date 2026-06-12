# CEEM ART Plan

## Product Intent

CEEM helps startups continuously understand what they expose to the public internet. The first version focuses on authorized domain monitoring: inventory, safe scans, findings, Slack alerts, authenticated dashboards, and remediation workflows.

The product is both a real SaaS foundation and a public learning project. That means each increment should teach clean Rust service design, secure product thinking, database modeling, frontend workflows, CI/CD hygiene, and responsible security automation.

## Agile Release Train

### Product Management

Responsibilities:

- Own product vision, market framing, roadmap, release themes, and success metrics.
- Keep the product startup-focused: fast setup, clear findings, low operational burden.
- Balance portfolio polish with real SaaS foundations.
- Decide which features are public-demo-safe.
- Maintain the release narrative in the README and docs.

Primary success metrics:

- Time from clone to local dashboard: under 20 minutes.
- Time from account creation to first domain scan: under 10 minutes after MVP auth exists.
- Findings include evidence, confidence, severity, and remediation.
- Slack alert delivery is observable and logged.
- No feature can scan an asset without authorization attestation.

### Product Owners

#### PO: Organizations, Auth, and Teams

Owns:

- User registration and login.
- Organization creation.
- Member invitations.
- Roles: owner, admin, member, viewer.
- Session lifecycle.
- Audit logs.

MVP acceptance:

- A user can create an organization.
- Organization data is isolated by org ID.
- Role checks protect write operations.
- Security-sensitive events are audited.

#### PO: Asset Inventory

Owns:

- Domain asset CRUD.
- Domain normalization and validation.
- Authorization attestation.
- Asset history.
- Later expansion to IP addresses, cloud imports, and passive discovery.

MVP acceptance:

- Domains cannot include schemes, paths, or unsupported characters.
- Duplicate domains are prevented per organization.
- The user must attest authorization before storing a scannable domain.

#### PO: Scanner and Findings

Owns:

- Scan request model.
- Scan scheduling.
- DNS, HTTP, HTTPS, TLS, and security header checks.
- Finding rules.
- Deduplication and reopening behavior.
- Severity and confidence scoring.

MVP acceptance:

- Manual scan can run for one authorized domain.
- Results are persisted with raw evidence.
- Findings are generated deterministically from evidence.
- Existing findings are updated instead of duplicated.

#### PO: Dashboard and Remediation

Owns:

- Authenticated dashboard.
- Asset list.
- Scan history.
- Findings list and detail.
- Remediation statuses.
- Assignment and notes.

MVP acceptance:

- Users can see organizational exposure at a glance.
- Users can filter findings by severity and status.
- Users can mark findings false positive, accepted risk, in progress, or remediated.
- Status changes are captured as finding events.

#### PO: Alerts and Integrations

Owns:

- Slack first.
- Alert rules.
- Delivery history.
- Suppression.
- Later email, webhook, GitHub Issues, Linear, Jira.

MVP acceptance:

- Organization admins can configure a Slack webhook.
- High and critical findings queue Slack alerts.
- Alert delivery success/failure is persisted.
- Alerts include asset, severity, finding title, and remediation.

### Business Analysis

BA responsibilities:

- Convert product intent into thin, testable vertical slices.
- Maintain glossary and data definitions.
- Write acceptance criteria.
- Identify sensitive workflow decisions.
- Keep uncertainty visible in requirements.

Core MVP user stories:

1. As an owner, I can create an organization so my team has an isolated workspace.
2. As an admin, I can invite teammates so remediation can be shared.
3. As an admin, I can add a domain I am authorized to monitor.
4. As an admin, I can manually trigger a scan for an authorized domain.
5. As a member, I can see scan status and history.
6. As a member, I can view findings with evidence and remediation guidance.
7. As a member, I can change finding status and leave notes.
8. As an admin, I can configure Slack alerts.
9. As an owner, I can review audit logs for material actions.

### Scrum Masters

Responsibilities:

- Protect sprint focus.
- Remove local development blockers.
- Keep stories thin enough to finish.
- Maintain Definition of Ready and Definition of Done.
- Run retrospectives that produce concrete improvements.

Cadence:

- Two-week sprints.
- Eight-week first Program Increment.
- Backlog refinement weekly.
- Sprint review at the end of every sprint.
- PI demo at the end of the increment.

Definition of Ready:

- User value is clear.
- Scope fits a sprint.
- Acceptance criteria are testable.
- Security implications are named.
- Data model impact is known.
- Observability requirement is known.

Definition of Done:

- Code compiles.
- Tests pass.
- Database migration exists when needed.
- API errors are explicit.
- Authz and tenancy are considered.
- Relevant docs are updated.
- User-facing behavior is demoable.

## Program Increment 1

PI 1 objective:

Build the smallest trustworthy CEEM that supports organizations, domain inventory, safe manual scans, findings, Slack alerts, and remediation tracking.

### Sprint 1: Foundation

Goals:

- Create Rust workspace.
- Create React dashboard shell.
- Add Docker Compose Postgres.
- Add initial migration.
- Add CI.
- Add product, architecture, and security docs.
- Create `/healthz`.

Exit criteria:

- `cargo test --workspace` passes.
- `npm run build` passes.
- README can onboard a new contributor.

### Sprint 2: Auth and Organizations

Goals:

- Implement user registration.
- Implement password hashing.
- Implement login/session model.
- Implement organization creation.
- Implement member roles.

Exit criteria:

- A user can register and create an organization.
- Protected API routes reject unauthenticated requests.
- Organization boundaries are enforced in queries.

### Sprint 3: Domain Inventory

Goals:

- Add domain CRUD.
- Store authorization attestation.
- Add domain normalization.
- Build dashboard asset list.

Exit criteria:

- Users can add, list, and archive domains.
- Invalid URL-like input is rejected.
- Duplicate domains are prevented.

### Sprint 4: Scan Engine MVP

Goals:

- Add scan jobs.
- Add manual scan trigger.
- Implement DNS checks.
- Implement HTTP/HTTPS reachability.
- Implement TLS certificate inspection.
- Persist raw scan evidence.

Exit criteria:

- A manual scan produces scan results for one domain.
- Scan failures are visible and logged.
- Scanner obeys rate limits.

### Sprint 5: Findings MVP

Goals:

- Add finding rules.
- Convert scan results to findings.
- Deduplicate findings by asset and rule.
- Add finding lifecycle transitions.

Exit criteria:

- Findings are visible in API and dashboard.
- Findings include evidence, confidence, severity, and remediation.
- Resolved findings can reopen if detected again.

### Sprint 6: Slack Alerts

Goals:

- Configure Slack webhook per organization.
- Queue alerts for high/critical findings.
- Deliver Slack messages from worker.
- Store alert status and errors.

Exit criteria:

- Slack alert can be tested from local development.
- Alert delivery is idempotent.
- Failed alerts are inspectable.

### Sprint 7: Remediation Workflow

Goals:

- Add remediation tasks.
- Add assignment.
- Add notes/events.
- Add dashboard workflow controls.

Exit criteria:

- Users can move findings through remediation statuses.
- Changes are audited.
- Dashboard supports the daily remediation loop.

### Sprint 8: Hardening and Public Release

Goals:

- Improve tests.
- Add seed data.
- Add screenshots.
- Add deployment guide.
- Prepare GitHub repository.
- Tag `v0.1.0`.

Exit criteria:

- Public README is coherent.
- Security model is explicit.
- Local setup is repeatable.
- Demo path works end to end.

## Program Increment 2

Themes:

- Scheduled scans.
- Change detection.
- Better dashboard filtering.
- Email and generic webhooks.
- CSV export.
- Deployment pipeline.
- Basic billing-readiness boundaries without implementing billing yet.

## Program Increment 3

Themes:

- Passive subdomain discovery.
- Certificate transparency lookups.
- Screenshot capture.
- GitHub Issues or Linear tickets.
- Risk trend charts.
- Cloud asset import.
- AI-assisted remediation summaries.

## Initial Risks

- Scanner scope creep could turn the product into an unsafe vulnerability scanner.
- Auth and multitenancy mistakes can create severe data exposure.
- Slack webhook secrets must be protected.
- Public repo must not include test secrets or real customer data.
- UI can become a generic admin template unless we keep workflows specific.

## Operating Decisions

- Build organizations and teams from day one.
- Start domain-only.
- Use Rust backend and React/TypeScript frontend.
- Plan for cloud deployment early.
- Slack is the first external alert channel.
- Preserve a public learning trail through docs and small, explainable commits.
