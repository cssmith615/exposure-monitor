use std::{collections::BTreeSet, net::IpAddr};

use ceem_shared::{
    DnsAddressRecord, DnsAddressRecordKind, DnsBaselineEvidence, DomainValidationError,
    validate_domain,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::net::lookup_host;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanIntensity {
    Passive,
    LowImpactActive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainScanRequest {
    pub domain: String,
    pub authorization_attested: bool,
    pub intensity: ScanIntensity,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScanRequestError {
    #[error("asset owner authorization must be attested before scanning")]
    AuthorizationRequired,
    #[error(transparent)]
    InvalidDomain(#[from] DomainValidationError),
}

#[derive(Debug, Error)]
pub enum DnsBaselineError {
    #[error(transparent)]
    InvalidDomain(#[from] DomainValidationError),
    #[error("DNS lookup failed: {0}")]
    LookupFailed(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreparedDomainScan {
    pub normalized_domain: String,
    pub intensity: ScanIntensity,
}

pub fn prepare_domain_scan(
    request: DomainScanRequest,
) -> Result<PreparedDomainScan, ScanRequestError> {
    if !request.authorization_attested {
        return Err(ScanRequestError::AuthorizationRequired);
    }

    Ok(PreparedDomainScan {
        normalized_domain: validate_domain(&request.domain)?,
        intensity: request.intensity,
    })
}

pub async fn resolve_dns_baseline(domain: &str) -> Result<DnsBaselineEvidence, DnsBaselineError> {
    let domain = validate_domain(domain)?;
    let mut addresses = BTreeSet::new();

    for socket_address in lookup_host((domain.as_str(), 443)).await? {
        let ip = socket_address.ip();
        let record_type = match ip {
            IpAddr::V4(_) => DnsAddressRecordKind::A,
            IpAddr::V6(_) => DnsAddressRecordKind::Aaaa,
        };

        addresses.insert((ip.to_string(), record_type));
    }

    Ok(DnsBaselineEvidence {
        domain,
        addresses: addresses
            .into_iter()
            .map(|(value, record_type)| DnsAddressRecord { record_type, value })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_authorization_attestation() {
        let request = DomainScanRequest {
            domain: "example.com".to_string(),
            authorization_attested: false,
            intensity: ScanIntensity::Passive,
        };

        assert_eq!(
            prepare_domain_scan(request).unwrap_err(),
            ScanRequestError::AuthorizationRequired
        );
    }

    #[test]
    fn prepares_authorized_domain_scan() {
        let request = DomainScanRequest {
            domain: "Example.COM.".to_string(),
            authorization_attested: true,
            intensity: ScanIntensity::Passive,
        };

        let scan = prepare_domain_scan(request).unwrap();

        assert_eq!(scan.normalized_domain, "example.com");
        assert_eq!(scan.intensity, ScanIntensity::Passive);
    }

    #[tokio::test]
    async fn rejects_invalid_dns_baseline_domain() {
        let error = resolve_dns_baseline("https://example.com")
            .await
            .unwrap_err();

        assert!(matches!(error, DnsBaselineError::InvalidDomain(_)));
    }
}
