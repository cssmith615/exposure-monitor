use ceem_shared::{Finding, Severity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlackMessage {
    pub text: String,
}

pub fn build_slack_finding_alert(finding: &Finding, asset_domain: &str) -> SlackMessage {
    SlackMessage {
        text: format!(
            "[CEEM] {:?} finding on {}: {}. Remediation: {}",
            finding.severity, asset_domain, finding.title, finding.remediation
        ),
    }
}

pub fn should_alert_slack(severity: Severity) -> bool {
    matches!(severity, Severity::High | Severity::Critical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ceem_shared::{Confidence, FindingStatus};
    use uuid::Uuid;

    #[test]
    fn only_alerts_for_high_and_critical() {
        assert!(!should_alert_slack(Severity::Medium));
        assert!(should_alert_slack(Severity::High));
        assert!(should_alert_slack(Severity::Critical));
    }

    #[test]
    fn builds_slack_payload_text() {
        let finding = Finding {
            id: Uuid::now_v7(),
            organization_id: Uuid::now_v7(),
            asset_id: Uuid::now_v7(),
            rule_id: "tls_certificate_expiring_soon".to_string(),
            title: "TLS certificate expires soon".to_string(),
            severity: Severity::High,
            status: FindingStatus::Open,
            confidence: Confidence::High,
            evidence: "Certificate expires in 12 days".to_string(),
            remediation: "Renew the certificate.".to_string(),
            first_seen_at: chrono::Utc::now(),
            last_seen_at: chrono::Utc::now(),
        };

        let payload = build_slack_finding_alert(&finding, "example.com");

        assert!(payload.text.contains("example.com"));
        assert!(payload.text.contains("TLS certificate expires soon"));
    }
}
