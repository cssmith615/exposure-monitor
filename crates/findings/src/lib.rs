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
        DnsAddressRecord, DnsAddressRecordKind, DnsBaselineEvidence, ScanEvidence, ScanResult,
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
}
