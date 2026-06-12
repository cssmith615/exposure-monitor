# CEEM Backlog

## Epic 1: Foundation

- Create Rust workspace.
- Create React dashboard shell.
- Add Docker Compose Postgres.
- Add initial migration.
- Add CI.
- Add README and docs.

## Epic 2: Auth and Organizations

- Register user.
- Login user.
- Hash passwords with Argon2.
- Create organization.
- Invite organization member.
- Assign member role.
- Enforce organization-scoped access.

## Epic 3: Domain Inventory

- Add domain.
- Validate domain input.
- Store authorization attestation.
- List organization domains.
- Archive domain.
- Show asset detail.

## Epic 4: Scanning

- Create scan job.
- Run manual scan.
- DNS lookup.
- HTTP reachability.
- HTTPS reachability.
- TLS certificate metadata.
- Security header capture.
- Persist scan evidence.

## Epic 5: Findings

- Define rules.
- Generate findings from evidence.
- Deduplicate findings.
- Reopen recurring findings.
- Change finding status.
- Add finding notes.

## Epic 6: Alerts

- Configure Slack webhook.
- Queue alert for high/critical finding.
- Deliver Slack alert.
- Store alert status.
- Retry failed alert.

## Epic 7: Dashboard

- Login screen.
- Organization switcher.
- Asset list.
- Scan history.
- Finding list.
- Finding detail.
- Remediation controls.
- Alert settings.

## Epic 8: Deployment

- Containerize API.
- Containerize worker.
- Build static frontend.
- Add production configuration doc.
- Add cloud deployment guide.
