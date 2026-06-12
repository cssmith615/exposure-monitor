# CEEM Agent and AI-Native Roadmap

This plan folds in the Perplexity discussion around Rust in red-team, gray-hat, and enterprise Linux contexts.

## CEEM Agent

`ceem-agent` is a future Rust host agent for Linux, with RHEL as the first packaging target. It extends CEEM from external-only domain monitoring into approved local inventory and evidence collection.

### V1 Responsibilities

- Enroll with the CEEM control plane using a one-time bootstrap token.
- Run as a systemd service with least-privilege defaults.
- Maintain an agent identity, heartbeat, version, capabilities, and local policy cache.
- Poll or subscribe for scoped jobs.
- Collect local certificate inventory, selected service metadata, host DNS configuration, and package/runtime facts.
- Return normalized events and evidence to CEEM.

### Guardrails

- No exploit execution.
- No credential dumping.
- No lateral movement automation.
- No local privilege escalation.
- No unsafely broad filesystem crawling.
- Every job must be policy-scoped and auditable.

### Identity Path

- V1: enrollment token exchanged for agent ID and scoped API credential.
- V2: short-lived credentials with rotation.
- V3: mTLS/SPIFFE-compatible identity for stronger workload trust.

### RHEL Packaging

- Build RPM package.
- Install systemd unit.
- Store config under `/etc/ceem-agent/`.
- Store state under `/var/lib/ceem-agent/`.
- Emit journald logs.
- Support `ceem-agent enroll`, `ceem-agent status`, and `ceem-agent doctor`.

## AI-Agent-Native Architecture

CEEM should use AI assistance as a bounded operator aid, not an autonomous actor.

### Internal Agent Roles

- Collector agent: proposes scan/enrichment jobs from approved assets and policies.
- Analyzer agent: summarizes evidence and explains likely risk.
- Triage agent: recommends severity, owner, and remediation next step.
- Watcher agent: detects repeated findings, noisy alerts, and stale remediation work.
- Operator copilot: answers grounded questions from CEEM data with citations to evidence, findings, audit logs, and docs.

### Approval Gates

Require explicit human approval before:

- Expanding scan scope.
- Suppressing alerts.
- Marking accepted risk or false positive.
- Sending external messages.
- Changing organization policy.
- Installing or enrolling host agents.

## Control Plane Additions

- `agents` table: ID, organization, hostname, version, status, capabilities, last heartbeat.
- `agent_enrollments` table: bootstrap token hash, creator, expiry, accepted agent.
- `agent_jobs` table: job type, scope, policy, status, attempts, lock metadata.
- `agent_events` table: normalized evidence, source agent, timestamps.
- UI surfaces for agent inventory, enrollment, heartbeat health, job history, and policy.

## Roadmap Placement

- V1 remains external domain monitoring with Postgres, worker, Slack, dashboard, and deployment.
- V2 adds `ceem-agent` enrollment, heartbeats, local certificate inventory, and RPM/systemd packaging.
- V3 adds mTLS identity, richer local posture checks, policy simulation, and grounded AI operator copilot.
