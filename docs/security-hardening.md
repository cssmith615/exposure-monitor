# Security Hardening Notes

This sprint adds the first production hardening layer:

- JWT sessions are cleared by the frontend when expired or when the API returns `401`.
- Auth endpoints have a basic in-process retry limiter.
- Register and login events are audit logged.
- CORS can be restricted with `CEEM_CORS_ORIGIN`.
- Alert delivery is worker-owned with retries, backoff, and persisted failure state.
- Findings carry a risk score for “needs attention” ordering.

## OWASP ASVS Alignment

Use OWASP ASVS as the continuing checklist for authentication, session management, access control, validation, logging, and configuration:

https://owasp.org/www-project-application-security-verification-standard/

Near-term ASVS follow-ups:

- Move auth rate limiting to durable shared state for multi-instance API deployments.
- Add session revocation storage instead of stateless JWT-only sessions.
- Add password reset and email verification flows.
- Add stricter production cookie/header policy if the frontend and API share an origin.
- Add structured audit export and retention settings.

## OWASP Secure Headers Alignment

CEEM already checks selected HTTP security headers during probes. Continue expanding rules from OWASP Secure Headers:

https://owasp.org/www-project-secure-headers/

Near-term header rules:

- Strict-Transport-Security presence and max-age quality.
- Content-Security-Policy presence.
- X-Content-Type-Options.
- Referrer-Policy.
- Permissions-Policy.

## CISA KEV-Inspired Prioritization

CISA KEV is CVE-centric, while the CEEM MVP currently monitors domain, DNS, TLS, and HTTP posture. CEEM therefore stores `kev_relevance = not_applicable_without_cve` in risk factors for now.

https://www.cisa.gov/known-exploited-vulnerabilities-catalog

When CEEM later ingests technology fingerprints or CVE evidence, KEV membership should become a high-weight risk factor.
