use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub const PRODUCT_NAME: &str = "CEEM";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthResponse {
    pub service: String,
    pub status: ServiceStatus,
    pub version: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceStatus {
    Ok,
    Degraded,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainAsset {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub domain: String,
    pub authorization_attested_by: Uuid,
    pub authorization_attested_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateDomainAssetRequest {
    pub domain: String,
    pub authorization_attested: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateDomainAssetResponse {
    pub asset: DomainAsset,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Canceled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanJob {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub asset_id: Uuid,
    pub requested_by: Uuid,
    pub status: ScanStatus,
    pub reason: Option<String>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateScanJobRequest {
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateScanJobResponse {
    pub scan_job: ScanJob,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum DnsAddressRecordKind {
    A,
    Aaaa,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsAddressRecord {
    pub record_type: DnsAddressRecordKind,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsBaselineEvidence {
    pub domain: String,
    pub addresses: Vec<DnsAddressRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityHeaderObservation {
    pub name: String,
    pub value: Option<String>,
    pub present: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsObservation {
    pub negotiated_https: bool,
    pub certificate_not_after: Option<DateTime<Utc>>,
    pub issuer: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpProbeEvidence {
    pub domain: String,
    pub scheme: String,
    pub status_code: Option<u16>,
    pub final_url: Option<String>,
    pub redirect_chain: Vec<String>,
    pub security_headers: Vec<SecurityHeaderObservation>,
    pub tls: Option<TlsObservation>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsPolicyEvidence {
    pub domain: String,
    pub spf_record: Option<String>,
    pub dmarc_record: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum ScanEvidence {
    DnsBaseline(DnsBaselineEvidence),
    HttpProbe(HttpProbeEvidence),
    DnsPolicy(DnsPolicyEvidence),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanResult {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub asset_id: Uuid,
    pub scan_job_id: Uuid,
    pub source: String,
    pub observed_at: DateTime<Utc>,
    pub evidence: ScanEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunDnsBaselineScanResponse {
    pub scan_job: ScanJob,
    pub scan_result: ScanResult,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserAccount {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Organization {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MemberRole {
    Owner,
    Admin,
    Member,
    Viewer,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrganizationMembership {
    pub organization_id: Uuid,
    pub user_id: Uuid,
    pub role: MemberRole,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrganizationMember {
    pub user: UserAccount,
    pub role: MemberRole,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrganizationSummary {
    pub organization: Organization,
    pub role: MemberRole,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterUserRequest {
    pub email: String,
    pub display_name: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterUserResponse {
    pub user: UserAccount,
    pub session: SessionToken,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoginResponse {
    pub user: UserAccount,
    pub session: SessionToken,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionToken {
    pub access_token: String,
    pub token_type: String,
    pub expires_in_seconds: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateOrganizationRequest {
    pub name: String,
    pub slug: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateOrganizationResponse {
    pub organization: Organization,
    pub membership: OrganizationMembership,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrganizationInvite {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub email: String,
    pub role: MemberRole,
    pub token: String,
    pub invited_by: Uuid,
    pub accepted_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateOrganizationInviteRequest {
    pub email: String,
    pub role: MemberRole,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateOrganizationInviteResponse {
    pub invite: OrganizationInvite,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcceptOrganizationInviteResponse {
    pub organization: Organization,
    pub membership: OrganizationMembership,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateMemberRoleRequest {
    pub role: MemberRole,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateMemberRoleResponse {
    pub membership: OrganizationMembership,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Open,
    AcceptedRisk,
    FalsePositive,
    InProgress,
    Remediated,
    Reopened,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub asset_id: Uuid,
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub status: FindingStatus,
    pub confidence: Confidence,
    pub evidence: String,
    pub remediation: String,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeriveFindingsResponse {
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateFindingStatusRequest {
    pub status: FindingStatus,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateFindingStatusResponse {
    pub finding: Finding,
    pub event: Option<FindingEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateFindingNoteRequest {
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateFindingNoteResponse {
    pub event: FindingEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingEvent {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub finding_id: Uuid,
    pub actor_user_id: Uuid,
    pub event_type: String,
    pub note: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlackNotificationChannel {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateSlackChannelRequest {
    pub name: String,
    pub webhook_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateSlackChannelResponse {
    pub channel: SlackNotificationChannel,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AlertStatus {
    Queued,
    Sent,
    Failed,
    Suppressed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Alert {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub finding_id: Uuid,
    pub notification_channel_id: Uuid,
    pub status: AlertStatus,
    pub payload: String,
    pub created_at: DateTime<Utc>,
    pub sent_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueueSlackAlertResponse {
    pub alert: Alert,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RemediationStatus {
    Open,
    InProgress,
    Blocked,
    Remediated,
    AcceptedRisk,
    FalsePositive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemediationTask {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub finding_id: Uuid,
    pub title: String,
    pub status: RemediationStatus,
    pub assignee: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateRemediationTaskRequest {
    pub title: Option<String>,
    pub assignee: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateRemediationTaskResponse {
    pub task: RemediationTask,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateRemediationStatusRequest {
    pub status: RemediationStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateRemediationStatusResponse {
    pub task: RemediationTask,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DomainValidationError {
    #[error("domain cannot be empty")]
    Empty,
    #[error("domain must not include a URL scheme")]
    ContainsScheme,
    #[error("domain must not include a path, query string, or fragment")]
    ContainsPath,
    #[error("domain must be 253 characters or fewer")]
    TooLong,
    #[error("domain labels must be 63 characters or fewer")]
    LabelTooLong,
    #[error("domain must contain at least one dot")]
    MissingDot,
    #[error("domain contains unsupported characters")]
    InvalidCharacters,
    #[error("domain labels cannot start or end with a hyphen")]
    InvalidHyphenPlacement,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SlugValidationError {
    #[error("slug cannot be empty")]
    Empty,
    #[error("slug must be 3 to 63 characters")]
    InvalidLength,
    #[error("slug must start and end with a lowercase letter or number")]
    InvalidBoundary,
    #[error("slug may contain lowercase letters, numbers, and single hyphens only")]
    InvalidCharacters,
    #[error("slug cannot contain consecutive hyphens")]
    ConsecutiveHyphen,
}

pub fn validate_domain(input: &str) -> Result<String, DomainValidationError> {
    let domain = input.trim().trim_end_matches('.').to_ascii_lowercase();

    if domain.is_empty() {
        return Err(DomainValidationError::Empty);
    }

    if domain.contains("://") {
        return Err(DomainValidationError::ContainsScheme);
    }

    if domain.contains('/') || domain.contains('?') || domain.contains('#') {
        return Err(DomainValidationError::ContainsPath);
    }

    if domain.len() > 253 {
        return Err(DomainValidationError::TooLong);
    }

    if !domain.contains('.') {
        return Err(DomainValidationError::MissingDot);
    }

    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(DomainValidationError::LabelTooLong);
        }

        if label.starts_with('-') || label.ends_with('-') {
            return Err(DomainValidationError::InvalidHyphenPlacement);
        }

        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(DomainValidationError::InvalidCharacters);
        }
    }

    Ok(domain)
}

pub fn validate_slug(input: &str) -> Result<String, SlugValidationError> {
    let slug = input.trim().to_ascii_lowercase();

    if slug.is_empty() {
        return Err(SlugValidationError::Empty);
    }

    if !(3..=63).contains(&slug.len()) {
        return Err(SlugValidationError::InvalidLength);
    }

    if slug.starts_with('-') || slug.ends_with('-') {
        return Err(SlugValidationError::InvalidBoundary);
    }

    if slug.contains("--") {
        return Err(SlugValidationError::ConsecutiveHyphen);
    }

    if !slug
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(SlugValidationError::InvalidCharacters);
    }

    Ok(slug)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_and_normalizes_domain() {
        assert_eq!(validate_domain(" Example.COM ").unwrap(), "example.com");
    }

    #[test]
    fn rejects_urls() {
        assert_eq!(
            validate_domain("https://example.com").unwrap_err(),
            DomainValidationError::ContainsScheme
        );
    }

    #[test]
    fn rejects_path_like_input() {
        assert_eq!(
            validate_domain("example.com/admin").unwrap_err(),
            DomainValidationError::ContainsPath
        );
    }

    #[test]
    fn validates_slug() {
        assert_eq!(validate_slug(" Acme-Security ").unwrap(), "acme-security");
    }

    #[test]
    fn rejects_consecutive_slug_hyphens() {
        assert_eq!(
            validate_slug("acme--security").unwrap_err(),
            SlugValidationError::ConsecutiveHyphen
        );
    }
}
