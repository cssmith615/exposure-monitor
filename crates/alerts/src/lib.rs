use ceem_shared::{Finding, Severity};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlackMessage {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlackDeliveryResult {
    pub status_code: u16,
}

#[derive(Debug, Error)]
pub enum SlackDeliveryError {
    #[error("Slack webhook URL must start with https://hooks.slack.com/")]
    InvalidWebhookUrl,
    #[error("Slack request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("Slack returned non-success status {status_code}: {body}")]
    NonSuccess { status_code: u16, body: String },
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

pub async fn deliver_slack_message(
    webhook_url: &str,
    message: &SlackMessage,
) -> Result<SlackDeliveryResult, SlackDeliveryError> {
    if !webhook_url.starts_with("https://hooks.slack.com/") {
        return Err(SlackDeliveryError::InvalidWebhookUrl);
    }

    let response = reqwest::Client::new()
        .post(webhook_url)
        .json(message)
        .send()
        .await?;
    let status = response.status();

    if !status.is_success() {
        return Err(SlackDeliveryError::NonSuccess {
            status_code: status.as_u16(),
            body: response.text().await.unwrap_or_default(),
        });
    }

    Ok(SlackDeliveryResult {
        status_code: status.as_u16(),
    })
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
            occurrence_count: 1,
            risk_score: 90,
            risk_factors: serde_json::json!({}),
            first_seen_at: chrono::Utc::now(),
            last_seen_at: chrono::Utc::now(),
        };

        let payload = build_slack_finding_alert(&finding, "example.com");

        assert!(payload.text.contains("example.com"));
        assert!(payload.text.contains("TLS certificate expires soon"));
    }

    #[tokio::test]
    async fn rejects_non_slack_webhook_urls() {
        let message = SlackMessage {
            text: "hello".to_string(),
        };
        let error = deliver_slack_message("https://example.com/webhook", &message)
            .await
            .unwrap_err();

        assert!(matches!(error, SlackDeliveryError::InvalidWebhookUrl));
    }
}
