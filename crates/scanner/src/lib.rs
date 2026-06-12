use std::{collections::BTreeSet, net::IpAddr, time::Duration};

use ceem_shared::{
    DnsAddressRecord, DnsAddressRecordKind, DnsBaselineEvidence, DnsPolicyEvidence,
    DomainValidationError, HttpProbeEvidence, SecurityHeaderObservation, TlsObservation,
    validate_domain,
};
use reqwest::{Client, StatusCode, Url, header::HeaderMap, redirect::Policy};
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

#[derive(Debug, Error)]
pub enum HttpProbeError {
    #[error(transparent)]
    InvalidDomain(#[from] DomainValidationError),
    #[error("HTTP client build failed: {0}")]
    ClientBuild(#[source] reqwest::Error),
}

#[derive(Debug, Error)]
pub enum DnsPolicyError {
    #[error(transparent)]
    InvalidDomain(#[from] DomainValidationError),
    #[error("DNS-over-HTTPS request failed: {0}")]
    Request(#[from] reqwest::Error),
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

pub async fn probe_http_endpoint(
    domain: &str,
    scheme: &str,
) -> Result<HttpProbeEvidence, HttpProbeError> {
    const MAX_REDIRECTS: usize = 5;

    let domain = validate_domain(domain)?;
    let scheme = match scheme {
        "http" | "https" => scheme.to_string(),
        _ => "https".to_string(),
    };
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(4))
        .timeout(Duration::from_secs(10))
        .redirect(Policy::none())
        .user_agent("CEEM/0.1 low-impact exposure monitor")
        .build()
        .map_err(HttpProbeError::ClientBuild)?;
    let mut url = format!("{scheme}://{domain}/");
    let mut redirect_chain = Vec::new();
    let mut final_status = None;
    let mut final_url = None;
    let mut final_headers = HeaderMap::new();
    let mut error = None;

    for _ in 0..=MAX_REDIRECTS {
        match client.get(&url).send().await {
            Ok(response) => {
                let status = response.status();
                final_status = Some(status.as_u16());
                final_url = Some(url.clone());
                final_headers = response.headers().clone();

                if !is_redirect(status) {
                    break;
                }

                let Some(location) = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                else {
                    break;
                };

                redirect_chain.push(url.clone());
                url = resolve_redirect_url(&url, location).unwrap_or_else(|| location.to_string());
            }
            Err(request_error) => {
                error = Some(request_error.to_string());
                break;
            }
        }
    }

    Ok(HttpProbeEvidence {
        domain,
        scheme: scheme.clone(),
        status_code: final_status,
        final_url,
        redirect_chain,
        security_headers: observe_security_headers(&final_headers),
        tls: (scheme == "https").then_some(TlsObservation {
            negotiated_https: final_status.is_some() && error.is_none(),
            certificate_not_after: None,
            issuer: None,
        }),
        error,
    })
}

pub async fn collect_dns_policy_baseline(
    domain: &str,
) -> Result<DnsPolicyEvidence, DnsPolicyError> {
    let domain = validate_domain(domain)?;
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(4))
        .timeout(Duration::from_secs(10))
        .user_agent("CEEM/0.1 low-impact exposure monitor")
        .build()
        .map_err(DnsPolicyError::Request)?;
    let spf_records = query_txt_records(&client, &domain).await?;
    let dmarc_records = query_txt_records(&client, &format!("_dmarc.{domain}")).await?;

    Ok(DnsPolicyEvidence {
        domain,
        spf_record: spf_records
            .into_iter()
            .find(|record| record.to_ascii_lowercase().contains("v=spf1")),
        dmarc_record: dmarc_records
            .into_iter()
            .find(|record| record.to_ascii_lowercase().contains("v=dmarc1")),
    })
}

fn is_redirect(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

fn resolve_redirect_url(current_url: &str, location: &str) -> Option<String> {
    Url::parse(current_url)
        .ok()
        .and_then(|base| base.join(location).ok())
        .map(|url| url.to_string())
}

fn observe_security_headers(headers: &HeaderMap) -> Vec<SecurityHeaderObservation> {
    [
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
    ]
    .into_iter()
    .map(|name| {
        let value = headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string);
        SecurityHeaderObservation {
            name: name.to_string(),
            present: value.is_some(),
            value,
        }
    })
    .collect()
}

#[derive(Debug, Deserialize)]
struct DnsJsonAnswer {
    data: String,
}

#[derive(Debug, Deserialize)]
struct DnsJsonResponse {
    #[serde(rename = "Answer")]
    answer: Option<Vec<DnsJsonAnswer>>,
}

async fn query_txt_records(client: &Client, name: &str) -> Result<Vec<String>, DnsPolicyError> {
    let response = client
        .get("https://cloudflare-dns.com/dns-query")
        .query(&[("name", name), ("type", "TXT")])
        .header(reqwest::header::ACCEPT, "application/dns-json")
        .send()
        .await?
        .error_for_status()?
        .json::<DnsJsonResponse>()
        .await?;

    Ok(response
        .answer
        .unwrap_or_default()
        .into_iter()
        .map(|answer| answer.data.replace('"', ""))
        .collect())
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

    #[tokio::test]
    async fn rejects_invalid_http_probe_domain() {
        let error = probe_http_endpoint("https://example.com", "https")
            .await
            .unwrap_err();

        assert!(matches!(error, HttpProbeError::InvalidDomain(_)));
    }

    #[test]
    fn resolves_relative_redirect_urls() {
        assert_eq!(
            resolve_redirect_url("https://example.com/a", "/login").unwrap(),
            "https://example.com/login"
        );
    }
}
