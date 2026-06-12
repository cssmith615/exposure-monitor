use ceem_shared::{Confidence, ScanEvidence, ScanResult, Severity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingRule {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub confidence: Confidence,
    pub remediation: &'static str,
}

pub const MVP_RULES: &[FindingRule] = &[
    FindingRule {
        id: "dns_public_address_observed",
        title: "Domain resolves to public address records",
        severity: Severity::Info,
        confidence: Confidence::High,
        remediation: "Confirm the observed address records are expected and owned by the organization.",
    },
    FindingRule {
        id: "dns_ipv6_address_observed",
        title: "Domain publishes IPv6 address records",
        severity: Severity::Low,
        confidence: Confidence::Medium,
        remediation: "Confirm IPv6 exposure is intentional and covered by monitoring, firewalling, and logging.",
    },
    FindingRule {
        id: "dns_no_address_records",
        title: "Domain has no A or AAAA records",
        severity: Severity::Medium,
        confidence: Confidence::High,
        remediation: "Confirm the domain should resolve publicly or remove it from monitored production inventory.",
    },
    FindingRule {
        id: "http_endpoint_unreachable",
        title: "HTTP endpoint is unreachable",
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        remediation: "Confirm the endpoint is expected to be reachable or remove it from monitored production inventory.",
    },
    FindingRule {
        id: "tls_certificate_expiring_soon",
        title: "TLS certificate expires soon",
        severity: Severity::Medium,
        confidence: Confidence::High,
        remediation: "Renew the certificate and confirm automated renewal is working.",
    },
    FindingRule {
        id: "http_missing_hsts",
        title: "HTTPS response is missing HSTS",
        severity: Severity::Low,
        confidence: Confidence::Medium,
        remediation: "Add a Strict-Transport-Security header after confirming HTTPS is stable.",
    },
    FindingRule {
        id: "dns_missing_dmarc",
        title: "Domain has no DMARC record",
        severity: Severity::Medium,
        confidence: Confidence::High,
        remediation: "Publish a DMARC TXT record and start with a monitoring policy if needed.",
    },
    FindingRule {
        id: "dns_missing_spf",
        title: "Domain has no SPF record",
        severity: Severity::Low,
        confidence: Confidence::High,
        remediation: "Publish an SPF TXT record that reflects authorized mail senders for the domain.",
    },
];

pub fn rule_by_id(id: &str) -> Option<&'static FindingRule> {
    MVP_RULES.iter().find(|rule| rule.id == id)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingDraft {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub evidence: String,
    pub remediation: String,
}

pub fn derive_findings_from_scan_result(scan_result: &ScanResult) -> Vec<FindingDraft> {
    match &scan_result.evidence {
        ScanEvidence::DnsBaseline(evidence) => {
            let mut drafts = Vec::new();

            if evidence.addresses.is_empty() {
                drafts.push(draft_from_rule(
                    "dns_no_address_records",
                    "Resolver returned no A or AAAA records.".to_string(),
                ));
                return drafts;
            }

            let values = evidence
                .addresses
                .iter()
                .map(|record| record.value.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            drafts.push(draft_from_rule(
                "dns_public_address_observed",
                format!(
                    "Observed {} public address record(s): {values}.",
                    evidence.addresses.len()
                ),
            ));

            if evidence
                .addresses
                .iter()
                .any(|record| record.value.contains(':'))
            {
                drafts.push(draft_from_rule(
                    "dns_ipv6_address_observed",
                    format!("Observed IPv6 DNS exposure for {}.", evidence.domain),
                ));
            }

            drafts
        }
        ScanEvidence::HttpProbe(evidence) => {
            let mut drafts = Vec::new();

            if let Some(error) = &evidence.error {
                drafts.push(draft_from_rule(
                    "http_endpoint_unreachable",
                    format!(
                        "{} probe for {} failed: {error}.",
                        evidence.scheme, evidence.domain
                    ),
                ));
                return drafts;
            }

            if evidence.scheme == "https"
                && evidence
                    .security_headers
                    .iter()
                    .any(|header| header.name == "strict-transport-security" && !header.present)
            {
                drafts.push(draft_from_rule(
                    "http_missing_hsts",
                    format!(
                        "HTTPS response for {} did not include HSTS.",
                        evidence.domain
                    ),
                ));
            }

            drafts
        }
        ScanEvidence::DnsPolicy(evidence) => {
            let mut drafts = Vec::new();

            if evidence.dmarc_record.is_none() {
                drafts.push(draft_from_rule(
                    "dns_missing_dmarc",
                    format!("No DMARC TXT record was observed for {}.", evidence.domain),
                ));
            }

            if evidence.spf_record.is_none() {
                drafts.push(draft_from_rule(
                    "dns_missing_spf",
                    format!("No SPF TXT record was observed for {}.", evidence.domain),
                ));
            }

            drafts
        }
    }
}

fn draft_from_rule(rule_id: &str, evidence: String) -> FindingDraft {
    let rule = rule_by_id(rule_id).expect("MVP rule id must exist");

    FindingDraft {
        rule_id: rule.id.to_string(),
        title: rule.title.to_string(),
        severity: rule.severity,
        confidence: rule.confidence,
        evidence,
        remediation: rule.remediation.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ceem_shared::{
        DnsAddressRecord, DnsAddressRecordKind, DnsBaselineEvidence, DnsPolicyEvidence,
        HttpProbeEvidence, ScanEvidence, ScanResult, SecurityHeaderObservation,
    };
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn finds_known_rule() {
        let rule = rule_by_id("dns_missing_dmarc").unwrap();
        assert_eq!(rule.severity, Severity::Medium);
    }

    #[test]
    fn derives_dns_address_finding() {
        let scan_result = ScanResult {
            id: Uuid::now_v7(),
            organization_id: Uuid::now_v7(),
            asset_id: Uuid::now_v7(),
            scan_job_id: Uuid::now_v7(),
            source: "dns_baseline".to_string(),
            observed_at: Utc::now(),
            evidence: ScanEvidence::DnsBaseline(DnsBaselineEvidence {
                domain: "example.com".to_string(),
                addresses: vec![DnsAddressRecord {
                    record_type: DnsAddressRecordKind::A,
                    value: "93.184.216.34".to_string(),
                }],
            }),
        };

        let findings = derive_findings_from_scan_result(&scan_result);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "dns_public_address_observed");
    }

    #[test]
    fn derives_http_security_header_finding() {
        let scan_result = ScanResult {
            id: Uuid::now_v7(),
            organization_id: Uuid::now_v7(),
            asset_id: Uuid::now_v7(),
            scan_job_id: Uuid::now_v7(),
            source: "http_probe".to_string(),
            observed_at: Utc::now(),
            evidence: ScanEvidence::HttpProbe(HttpProbeEvidence {
                domain: "example.com".to_string(),
                scheme: "https".to_string(),
                status_code: Some(200),
                final_url: Some("https://example.com/".to_string()),
                redirect_chain: Vec::new(),
                security_headers: vec![SecurityHeaderObservation {
                    name: "strict-transport-security".to_string(),
                    value: None,
                    present: false,
                }],
                tls: None,
                error: None,
            }),
        };

        let findings = derive_findings_from_scan_result(&scan_result);

        assert_eq!(findings[0].rule_id, "http_missing_hsts");
    }

    #[test]
    fn derives_dns_policy_findings() {
        let scan_result = ScanResult {
            id: Uuid::now_v7(),
            organization_id: Uuid::now_v7(),
            asset_id: Uuid::now_v7(),
            scan_job_id: Uuid::now_v7(),
            source: "dns_policy".to_string(),
            observed_at: Utc::now(),
            evidence: ScanEvidence::DnsPolicy(DnsPolicyEvidence {
                domain: "example.com".to_string(),
                spf_record: None,
                dmarc_record: None,
            }),
        };

        let findings = derive_findings_from_scan_result(&scan_result);

        assert_eq!(findings.len(), 2);
    }
}
