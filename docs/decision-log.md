# Decision Log

## 2026-06-12: Product Name

Decision: Use CEEM as the product name.

Reason: Short for Continuous External Exposure Monitor and aligned with the user's selected name.

## 2026-06-12: Backend and Frontend Split

Decision: Use Rust for backend services and React/TypeScript for the dashboard.

Reason: Rust carries the learning goal and scanner/backend performance/security story. React/TypeScript keeps the dashboard pragmatic and portfolio-friendly.

## 2026-06-12: Organizations from Day One

Decision: Build organizations, members, and roles into the first schema.

Reason: Retrofitting multitenancy later is risky. CEEM's target users are teams at startups, not only individuals.

## 2026-06-12: Domain-Only MVP

Decision: MVP supports domains only. IP addresses are deferred.

Reason: Domains allow useful DNS, HTTP, HTTPS, TLS, and header checks while keeping scanner risk lower.

## 2026-06-12: Slack First

Decision: Slack is the first external alert channel.

Reason: Startup teams commonly live in Slack, and webhook-based delivery is simple enough for the first integration.
