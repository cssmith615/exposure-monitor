use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use axum::{
    Json, Router,
    extract::{FromRef, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use ceem_alerts::build_slack_finding_alert;
use ceem_auth::{
    PasswordPolicy, hash_password, issue_session_token, validate_password_policy, verify_password,
    verify_session_token,
};
use ceem_findings::derive_findings_from_scan_result;
use ceem_scanner::{collect_dns_policy_baseline, probe_http_endpoint, resolve_dns_baseline};
use ceem_shared::{
    AcceptOrganizationInviteResponse, Alert, AlertStatus, CreateDomainAssetRequest,
    CreateDomainAssetResponse, CreateFindingNoteRequest, CreateFindingNoteResponse,
    CreateOrganizationInviteRequest, CreateOrganizationInviteResponse, CreateOrganizationRequest,
    CreateOrganizationResponse, CreateRemediationTaskRequest, CreateRemediationTaskResponse,
    CreateScanJobRequest, CreateScanJobResponse, CreateSlackChannelRequest,
    CreateSlackChannelResponse, DeriveFindingsResponse, DomainAsset, Finding, FindingEvent,
    FindingStatus, HealthResponse, LoginRequest, LoginResponse, MemberRole, Organization,
    OrganizationInvite, OrganizationMember, OrganizationMembership, OrganizationSummary,
    PRODUCT_NAME, QueueSlackAlertResponse, RegisterUserRequest, RegisterUserResponse,
    RemediationStatus, RemediationTask, RunDnsBaselineScanResponse, ScanEvidence, ScanJob,
    ScanResult, ScanStatus, ServiceStatus, SessionToken, SlackNotificationChannel,
    UpdateFindingStatusRequest, UpdateFindingStatusResponse, UpdateMemberRoleRequest,
    UpdateMemberRoleResponse, UpdateRemediationStatusRequest, UpdateRemediationStatusResponse,
    UserAccount, validate_domain, validate_slug,
};
use chrono::Utc;
use serde::Serialize;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let bind_addr =
        std::env::var("CEEM_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    info!(%bind_addr, "starting CEEM API");

    axum::serve(listener, app()).await?;
    Ok(())
}

fn app() -> Router {
    let state = AppState::default();

    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/auth/register", post(register_user))
        .route("/v1/auth/login", post(login_user))
        .route(
            "/v1/organizations",
            post(create_organization).get(list_organizations),
        )
        .route(
            "/v1/organizations/{organization_id}/members",
            get(list_organization_members),
        )
        .route(
            "/v1/organizations/{organization_id}/members/{member_user_id}/role",
            post(update_member_role),
        )
        .route(
            "/v1/organizations/{organization_id}/invites",
            post(create_organization_invite),
        )
        .route(
            "/v1/organization-invites/{token}/accept",
            post(accept_organization_invite),
        )
        .route(
            "/v1/organizations/{organization_id}/domain-assets",
            post(create_domain_asset).get(list_domain_assets),
        )
        .route(
            "/v1/organizations/{organization_id}/domain-assets/{asset_id}/scan-jobs",
            post(create_scan_job),
        )
        .route(
            "/v1/organizations/{organization_id}/scan-jobs",
            get(list_scan_jobs),
        )
        .route(
            "/v1/organizations/{organization_id}/scan-jobs/{scan_job_id}/run-dns-baseline",
            post(run_dns_baseline_scan),
        )
        .route(
            "/v1/organizations/{organization_id}/scan-jobs/{scan_job_id}/run-http-probe",
            post(run_http_probe_scan),
        )
        .route(
            "/v1/organizations/{organization_id}/scan-jobs/{scan_job_id}/run-dns-policy",
            post(run_dns_policy_scan),
        )
        .route(
            "/v1/organizations/{organization_id}/scan-results",
            get(list_scan_results),
        )
        .route(
            "/v1/organizations/{organization_id}/scan-results/{scan_result_id}/derive-findings",
            post(derive_findings),
        )
        .route(
            "/v1/organizations/{organization_id}/findings",
            get(list_findings),
        )
        .route(
            "/v1/organizations/{organization_id}/findings/{finding_id}/status",
            post(update_finding_status),
        )
        .route(
            "/v1/organizations/{organization_id}/findings/{finding_id}/notes",
            post(create_finding_note).get(list_finding_notes),
        )
        .route(
            "/v1/organizations/{organization_id}/slack-channels",
            post(create_slack_channel),
        )
        .route(
            "/v1/organizations/{organization_id}/findings/{finding_id}/slack-alerts",
            post(queue_slack_alert),
        )
        .route(
            "/v1/organizations/{organization_id}/alerts",
            get(list_alerts),
        )
        .route(
            "/v1/organizations/{organization_id}/findings/{finding_id}/remediation-tasks",
            post(create_remediation_task),
        )
        .route(
            "/v1/organizations/{organization_id}/remediation-tasks",
            get(list_remediation_tasks),
        )
        .route(
            "/v1/organizations/{organization_id}/remediation-tasks/{task_id}/status",
            post(update_remediation_status),
        )
        .with_state(state)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse {
        service: PRODUCT_NAME.to_string(),
        status: ServiceStatus::Ok,
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).json().init();
}

#[derive(Clone, Default)]
struct AppState {
    repository: Arc<Mutex<InMemoryRepository>>,
}

impl FromRef<AppState> for Arc<Mutex<InMemoryRepository>> {
    fn from_ref(state: &AppState) -> Self {
        Arc::clone(&state.repository)
    }
}

#[derive(Default)]
struct InMemoryRepository {
    users_by_id: HashMap<Uuid, UserAccount>,
    user_ids_by_email: HashMap<String, Uuid>,
    password_hashes_by_user_id: HashMap<Uuid, String>,
    organizations_by_id: HashMap<Uuid, Organization>,
    organization_ids_by_slug: HashMap<String, Uuid>,
    memberships: Vec<OrganizationMembership>,
    organization_invites_by_token: HashMap<String, OrganizationInvite>,
    domain_assets_by_id: HashMap<Uuid, DomainAsset>,
    domain_asset_ids_by_org_domain: HashMap<(Uuid, String), Uuid>,
    scan_jobs_by_id: HashMap<Uuid, ScanJob>,
    scan_results_by_id: HashMap<Uuid, ScanResult>,
    findings_by_id: HashMap<Uuid, Finding>,
    finding_ids_by_asset_rule: HashMap<(Uuid, String), Uuid>,
    finding_events_by_id: HashMap<Uuid, FindingEvent>,
    slack_channels_by_id: HashMap<Uuid, SlackNotificationChannel>,
    slack_secret_refs_by_id: HashMap<Uuid, String>,
    alerts_by_id: HashMap<Uuid, Alert>,
    remediation_tasks_by_id: HashMap<Uuid, RemediationTask>,
}

async fn register_user(
    State(repository): State<Arc<Mutex<InMemoryRepository>>>,
    Json(request): Json<RegisterUserRequest>,
) -> Result<Json<RegisterUserResponse>, ApiError> {
    let email = normalize_email(&request.email)?;
    let display_name = validate_display_name(&request.display_name)?;
    validate_password_policy(&request.password, &PasswordPolicy::default())
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let password_hash = hash_password(&request.password).map_err(|_| ApiError::internal())?;

    let mut repository = repository.lock().map_err(|_| ApiError::internal())?;

    if repository.user_ids_by_email.contains_key(&email) {
        return Err(ApiError::conflict("email is already registered"));
    }

    let user = UserAccount {
        id: Uuid::now_v7(),
        email: email.clone(),
        display_name,
        created_at: Utc::now(),
    };

    repository.user_ids_by_email.insert(email, user.id);
    repository
        .password_hashes_by_user_id
        .insert(user.id, password_hash);
    repository.users_by_id.insert(user.id, user.clone());

    let session = session_for_user(user.id)?;

    Ok(Json(RegisterUserResponse { user, session }))
}

async fn login_user(
    State(repository): State<Arc<Mutex<InMemoryRepository>>>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let email = normalize_email(&request.email)?;
    let repository = repository.lock().map_err(|_| ApiError::internal())?;
    let user_id = repository
        .user_ids_by_email
        .get(&email)
        .copied()
        .ok_or_else(|| ApiError::unauthorized("email or password is incorrect"))?;
    let password_hash = repository
        .password_hashes_by_user_id
        .get(&user_id)
        .ok_or_else(ApiError::internal)?;

    if !verify_password(&request.password, password_hash).map_err(|_| ApiError::internal())? {
        return Err(ApiError::unauthorized("email or password is incorrect"));
    }

    let user = repository
        .users_by_id
        .get(&user_id)
        .cloned()
        .ok_or_else(ApiError::internal)?;
    let session = session_for_user(user.id)?;

    Ok(Json(LoginResponse { user, session }))
}

async fn create_organization(
    State(repository): State<Arc<Mutex<InMemoryRepository>>>,
    headers: HeaderMap,
    Json(request): Json<CreateOrganizationRequest>,
) -> Result<Json<CreateOrganizationResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let name = validate_organization_name(&request.name)?;
    let slug =
        validate_slug(&request.slug).map_err(|error| ApiError::bad_request(error.to_string()))?;

    let mut repository = repository.lock().map_err(|_| ApiError::internal())?;

    if !repository.users_by_id.contains_key(&user_id) {
        return Err(ApiError::unauthorized("user does not exist"));
    }

    if repository.organization_ids_by_slug.contains_key(&slug) {
        return Err(ApiError::conflict("organization slug is already taken"));
    }

    let now = Utc::now();
    let organization = Organization {
        id: Uuid::now_v7(),
        name,
        slug: slug.clone(),
        created_at: now,
    };
    let membership = OrganizationMembership {
        organization_id: organization.id,
        user_id,
        role: MemberRole::Owner,
        created_at: now,
    };

    repository
        .organization_ids_by_slug
        .insert(slug, organization.id);
    repository
        .organizations_by_id
        .insert(organization.id, organization.clone());
    repository.memberships.push(membership.clone());

    Ok(Json(CreateOrganizationResponse {
        organization,
        membership,
    }))
}

async fn list_organizations(
    State(repository): State<Arc<Mutex<InMemoryRepository>>>,
    headers: HeaderMap,
) -> Result<Json<Vec<OrganizationSummary>>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let repository = repository.lock().map_err(|_| ApiError::internal())?;

    if !repository.users_by_id.contains_key(&user_id) {
        return Err(ApiError::unauthorized("user does not exist"));
    }

    let organizations = repository
        .memberships
        .iter()
        .filter(|membership| membership.user_id == user_id)
        .filter_map(|membership| {
            repository
                .organizations_by_id
                .get(&membership.organization_id)
                .map(|organization| OrganizationSummary {
                    organization: organization.clone(),
                    role: membership.role,
                })
        })
        .collect();

    Ok(Json(organizations))
}

async fn list_organization_members(
    State(repository): State<Arc<Mutex<InMemoryRepository>>>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<Vec<OrganizationMember>>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let repository = repository.lock().map_err(|_| ApiError::internal())?;
    repository.require_membership(user_id, organization_id)?;

    let mut members = repository
        .memberships
        .iter()
        .filter(|membership| membership.organization_id == organization_id)
        .filter_map(|membership| {
            repository
                .users_by_id
                .get(&membership.user_id)
                .map(|user| OrganizationMember {
                    user: user.clone(),
                    role: membership.role,
                    created_at: membership.created_at,
                })
        })
        .collect::<Vec<_>>();

    members.sort_by(|left, right| left.user.email.cmp(&right.user.email));

    Ok(Json(members))
}

async fn create_organization_invite(
    State(repository): State<Arc<Mutex<InMemoryRepository>>>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
    Json(request): Json<CreateOrganizationInviteRequest>,
) -> Result<Json<CreateOrganizationInviteResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let email = normalize_email(&request.email)?;
    let mut repository = repository.lock().map_err(|_| ApiError::internal())?;
    let role = repository.require_membership(user_id, organization_id)?;

    if !matches!(role, MemberRole::Owner | MemberRole::Admin) {
        return Err(ApiError::forbidden(
            "only organization owners and admins can invite members",
        ));
    }

    if matches!(request.role, MemberRole::Owner) && !matches!(role, MemberRole::Owner) {
        return Err(ApiError::forbidden("only owners can invite another owner"));
    }

    let invite = OrganizationInvite {
        id: Uuid::now_v7(),
        organization_id,
        email,
        role: request.role,
        token: Uuid::now_v7().to_string(),
        invited_by: user_id,
        accepted_at: None,
        created_at: Utc::now(),
    };

    repository
        .organization_invites_by_token
        .insert(invite.token.clone(), invite.clone());

    Ok(Json(CreateOrganizationInviteResponse { invite }))
}

async fn accept_organization_invite(
    State(repository): State<Arc<Mutex<InMemoryRepository>>>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Result<Json<AcceptOrganizationInviteResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let mut repository = repository.lock().map_err(|_| ApiError::internal())?;
    let user = repository
        .users_by_id
        .get(&user_id)
        .cloned()
        .ok_or_else(|| ApiError::unauthorized("user does not exist"))?;
    let invite = repository
        .organization_invites_by_token
        .get_mut(&token)
        .ok_or_else(|| ApiError::not_found("organization invite does not exist"))?;

    if invite.accepted_at.is_some() {
        return Err(ApiError::conflict(
            "organization invite has already been accepted",
        ));
    }

    if invite.email != user.email {
        return Err(ApiError::forbidden(
            "organization invite belongs to a different email address",
        ));
    }

    invite.accepted_at = Some(Utc::now());
    let invite = invite.clone();
    let membership = OrganizationMembership {
        organization_id: invite.organization_id,
        user_id,
        role: invite.role,
        created_at: Utc::now(),
    };

    if let Some(existing) = repository.memberships.iter_mut().find(|membership| {
        membership.organization_id == invite.organization_id && membership.user_id == user_id
    }) {
        existing.role = invite.role;
    } else {
        repository.memberships.push(membership.clone());
    }

    let organization = repository
        .organizations_by_id
        .get(&invite.organization_id)
        .cloned()
        .ok_or_else(ApiError::internal)?;

    Ok(Json(AcceptOrganizationInviteResponse {
        organization,
        membership,
    }))
}

async fn update_member_role(
    State(repository): State<Arc<Mutex<InMemoryRepository>>>,
    headers: HeaderMap,
    Path((organization_id, member_user_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<UpdateMemberRoleRequest>,
) -> Result<Json<UpdateMemberRoleResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let mut repository = repository.lock().map_err(|_| ApiError::internal())?;
    let actor_role = repository.require_membership(user_id, organization_id)?;

    if !matches!(actor_role, MemberRole::Owner | MemberRole::Admin) {
        return Err(ApiError::forbidden(
            "only organization owners and admins can update member roles",
        ));
    }

    if matches!(request.role, MemberRole::Owner) && !matches!(actor_role, MemberRole::Owner) {
        return Err(ApiError::forbidden("only owners can assign owner role"));
    }

    let membership = repository
        .memberships
        .iter_mut()
        .find(|membership| {
            membership.organization_id == organization_id && membership.user_id == member_user_id
        })
        .ok_or_else(|| ApiError::not_found("organization member does not exist"))?;

    membership.role = request.role;

    Ok(Json(UpdateMemberRoleResponse {
        membership: membership.clone(),
    }))
}

async fn create_domain_asset(
    State(repository): State<Arc<Mutex<InMemoryRepository>>>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
    Json(request): Json<CreateDomainAssetRequest>,
) -> Result<Json<CreateDomainAssetResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;

    if !request.authorization_attested {
        return Err(ApiError::bad_request(
            "authorization attestation is required before adding a domain",
        ));
    }

    let domain = validate_domain(&request.domain)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let mut repository = repository.lock().map_err(|_| ApiError::internal())?;
    let role = repository.require_membership(user_id, organization_id)?;

    if !matches!(role, MemberRole::Owner | MemberRole::Admin) {
        return Err(ApiError::forbidden(
            "only organization owners and admins can add monitored domains",
        ));
    }

    let key = (organization_id, domain.clone());

    if repository.domain_asset_ids_by_org_domain.contains_key(&key) {
        return Err(ApiError::conflict(
            "domain is already monitored by this organization",
        ));
    }

    let now = Utc::now();
    let asset = DomainAsset {
        id: Uuid::now_v7(),
        organization_id,
        domain,
        authorization_attested_by: user_id,
        authorization_attested_at: now,
        created_at: now,
    };

    repository
        .domain_asset_ids_by_org_domain
        .insert(key, asset.id);
    repository
        .domain_assets_by_id
        .insert(asset.id, asset.clone());

    Ok(Json(CreateDomainAssetResponse { asset }))
}

async fn list_domain_assets(
    State(repository): State<Arc<Mutex<InMemoryRepository>>>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<Vec<DomainAsset>>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let repository = repository.lock().map_err(|_| ApiError::internal())?;
    repository.require_membership(user_id, organization_id)?;

    let mut assets = repository
        .domain_assets_by_id
        .values()
        .filter(|asset| asset.organization_id == organization_id)
        .cloned()
        .collect::<Vec<_>>();

    assets.sort_by(|left, right| left.domain.cmp(&right.domain));

    Ok(Json(assets))
}

async fn create_scan_job(
    State(repository): State<Arc<Mutex<InMemoryRepository>>>,
    headers: HeaderMap,
    Path((organization_id, asset_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<CreateScanJobRequest>,
) -> Result<Json<CreateScanJobResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let reason = validate_scan_reason(request.reason)?;
    let mut repository = repository.lock().map_err(|_| ApiError::internal())?;
    let role = repository.require_membership(user_id, organization_id)?;

    if matches!(role, MemberRole::Viewer) {
        return Err(ApiError::forbidden(
            "viewers cannot trigger external exposure scans",
        ));
    }

    let asset = repository
        .domain_assets_by_id
        .get(&asset_id)
        .ok_or_else(|| ApiError::not_found("domain asset does not exist"))?;

    if asset.organization_id != organization_id {
        return Err(ApiError::not_found(
            "domain asset does not belong to this organization",
        ));
    }

    let scan_job = ScanJob {
        id: Uuid::now_v7(),
        organization_id,
        asset_id,
        requested_by: user_id,
        status: ScanStatus::Queued,
        reason,
        created_at: Utc::now(),
        started_at: None,
        completed_at: None,
    };

    repository
        .scan_jobs_by_id
        .insert(scan_job.id, scan_job.clone());

    Ok(Json(CreateScanJobResponse { scan_job }))
}

async fn list_scan_jobs(
    State(repository): State<Arc<Mutex<InMemoryRepository>>>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<Vec<ScanJob>>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let repository = repository.lock().map_err(|_| ApiError::internal())?;
    repository.require_membership(user_id, organization_id)?;

    let mut scan_jobs = repository
        .scan_jobs_by_id
        .values()
        .filter(|scan_job| scan_job.organization_id == organization_id)
        .cloned()
        .collect::<Vec<_>>();

    scan_jobs.sort_by(|left, right| right.created_at.cmp(&left.created_at));

    Ok(Json(scan_jobs))
}

fn claim_scan_job_asset(
    repository: &Arc<Mutex<InMemoryRepository>>,
    user_id: Uuid,
    organization_id: Uuid,
    scan_job_id: Uuid,
) -> Result<(Uuid, String), ApiError> {
    let mut repository = repository.lock().map_err(|_| ApiError::internal())?;
    let role = repository.require_membership(user_id, organization_id)?;

    if matches!(role, MemberRole::Viewer) {
        return Err(ApiError::forbidden("viewers cannot run scan jobs"));
    }

    let scan_job_asset_id = {
        let scan_job = repository
            .scan_jobs_by_id
            .get_mut(&scan_job_id)
            .ok_or_else(|| ApiError::not_found("scan job does not exist"))?;

        if scan_job.organization_id != organization_id {
            return Err(ApiError::not_found(
                "scan job does not belong to this organization",
            ));
        }

        if scan_job.status != ScanStatus::Queued {
            return Err(ApiError::conflict("only queued scan jobs can be run"));
        }

        scan_job.status = ScanStatus::Running;
        scan_job.started_at = Some(Utc::now());
        scan_job.asset_id
    };

    let asset = repository
        .domain_assets_by_id
        .get(&scan_job_asset_id)
        .ok_or_else(|| ApiError::not_found("domain asset does not exist"))?;

    Ok((asset.id, asset.domain.clone()))
}

fn complete_scan_job_with_result(
    repository: &Arc<Mutex<InMemoryRepository>>,
    scan_job_id: Uuid,
    scan_result: ScanResult,
) -> Result<ScanJob, ApiError> {
    let mut repository = repository.lock().map_err(|_| ApiError::internal())?;
    let completed_at = Utc::now();
    let scan_job = repository
        .scan_jobs_by_id
        .get_mut(&scan_job_id)
        .ok_or_else(|| ApiError::not_found("scan job does not exist"))?;
    scan_job.status = ScanStatus::Completed;
    scan_job.completed_at = Some(completed_at);
    let scan_job = scan_job.clone();

    repository
        .scan_results_by_id
        .insert(scan_result.id, scan_result);

    Ok(scan_job)
}

async fn run_dns_baseline_scan(
    State(repository): State<Arc<Mutex<InMemoryRepository>>>,
    headers: HeaderMap,
    Path((organization_id, scan_job_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<RunDnsBaselineScanResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let (asset_id, domain) = {
        let mut repository = repository.lock().map_err(|_| ApiError::internal())?;
        let role = repository.require_membership(user_id, organization_id)?;

        if matches!(role, MemberRole::Viewer) {
            return Err(ApiError::forbidden("viewers cannot run scan jobs"));
        }

        let scan_job_asset_id = {
            let scan_job = repository
                .scan_jobs_by_id
                .get_mut(&scan_job_id)
                .ok_or_else(|| ApiError::not_found("scan job does not exist"))?;

            if scan_job.organization_id != organization_id {
                return Err(ApiError::not_found(
                    "scan job does not belong to this organization",
                ));
            }

            if scan_job.status != ScanStatus::Queued {
                return Err(ApiError::conflict("only queued scan jobs can be run"));
            }

            scan_job.status = ScanStatus::Running;
            scan_job.started_at = Some(Utc::now());
            scan_job.asset_id
        };

        let asset = repository
            .domain_assets_by_id
            .get(&scan_job_asset_id)
            .ok_or_else(|| ApiError::not_found("domain asset does not exist"))?;

        (asset.id, asset.domain.clone())
    };

    let resolved = resolve_dns_baseline(&domain).await;
    let mut repository = repository.lock().map_err(|_| ApiError::internal())?;
    let completed_at = Utc::now();

    match resolved {
        Ok(evidence) => {
            let scan_result = ScanResult {
                id: Uuid::now_v7(),
                organization_id,
                asset_id,
                scan_job_id,
                source: "dns_baseline".to_string(),
                observed_at: completed_at,
                evidence: ScanEvidence::DnsBaseline(evidence),
            };

            let scan_job = repository
                .scan_jobs_by_id
                .get_mut(&scan_job_id)
                .ok_or_else(|| ApiError::not_found("scan job does not exist"))?;
            scan_job.status = ScanStatus::Completed;
            scan_job.completed_at = Some(completed_at);
            let scan_job = scan_job.clone();

            repository
                .scan_results_by_id
                .insert(scan_result.id, scan_result.clone());

            Ok(Json(RunDnsBaselineScanResponse {
                scan_job,
                scan_result,
            }))
        }
        Err(error) => {
            if let Some(scan_job) = repository.scan_jobs_by_id.get_mut(&scan_job_id) {
                scan_job.status = ScanStatus::Failed;
                scan_job.completed_at = Some(completed_at);
            }

            Err(ApiError::bad_gateway(format!(
                "DNS baseline scan failed: {error}"
            )))
        }
    }
}

async fn run_http_probe_scan(
    State(repository): State<Arc<Mutex<InMemoryRepository>>>,
    headers: HeaderMap,
    Path((organization_id, scan_job_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<RunDnsBaselineScanResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let (asset_id, domain) =
        claim_scan_job_asset(&repository, user_id, organization_id, scan_job_id)?;
    let observed_at = Utc::now();
    let evidence = probe_http_endpoint(&domain, "https")
        .await
        .map_err(|error| ApiError::bad_gateway(format!("HTTPS probe failed: {error}")))?;
    let scan_result = ScanResult {
        id: Uuid::now_v7(),
        organization_id,
        asset_id,
        scan_job_id,
        source: "http_probe".to_string(),
        observed_at,
        evidence: ScanEvidence::HttpProbe(evidence),
    };
    let scan_job = complete_scan_job_with_result(&repository, scan_job_id, scan_result.clone())?;

    Ok(Json(RunDnsBaselineScanResponse {
        scan_job,
        scan_result,
    }))
}

async fn run_dns_policy_scan(
    State(repository): State<Arc<Mutex<InMemoryRepository>>>,
    headers: HeaderMap,
    Path((organization_id, scan_job_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<RunDnsBaselineScanResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let (asset_id, domain) =
        claim_scan_job_asset(&repository, user_id, organization_id, scan_job_id)?;
    let observed_at = Utc::now();
    let evidence = collect_dns_policy_baseline(&domain)
        .await
        .map_err(|error| ApiError::bad_gateway(format!("DNS policy scan failed: {error}")))?;
    let scan_result = ScanResult {
        id: Uuid::now_v7(),
        organization_id,
        asset_id,
        scan_job_id,
        source: "dns_policy".to_string(),
        observed_at,
        evidence: ScanEvidence::DnsPolicy(evidence),
    };
    let scan_job = complete_scan_job_with_result(&repository, scan_job_id, scan_result.clone())?;

    Ok(Json(RunDnsBaselineScanResponse {
        scan_job,
        scan_result,
    }))
}

async fn list_scan_results(
    State(repository): State<Arc<Mutex<InMemoryRepository>>>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<Vec<ScanResult>>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let repository = repository.lock().map_err(|_| ApiError::internal())?;
    repository.require_membership(user_id, organization_id)?;

    let mut scan_results = repository
        .scan_results_by_id
        .values()
        .filter(|scan_result| scan_result.organization_id == organization_id)
        .cloned()
        .collect::<Vec<_>>();

    scan_results.sort_by(|left, right| right.observed_at.cmp(&left.observed_at));

    Ok(Json(scan_results))
}

async fn derive_findings(
    State(repository): State<Arc<Mutex<InMemoryRepository>>>,
    headers: HeaderMap,
    Path((organization_id, scan_result_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<DeriveFindingsResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let mut repository = repository.lock().map_err(|_| ApiError::internal())?;
    repository.require_membership(user_id, organization_id)?;

    let scan_result = repository
        .scan_results_by_id
        .get(&scan_result_id)
        .ok_or_else(|| ApiError::not_found("scan result does not exist"))?
        .clone();

    if scan_result.organization_id != organization_id {
        return Err(ApiError::not_found(
            "scan result does not belong to this organization",
        ));
    }

    let now = Utc::now();
    let mut findings = Vec::new();
    let mut response_indexes_by_finding_id = HashMap::new();

    for draft in derive_findings_from_scan_result(&scan_result) {
        let key = (scan_result.asset_id, draft.rule_id.clone());

        let finding =
            if let Some(finding_id) = repository.finding_ids_by_asset_rule.get(&key).copied() {
                let finding = repository
                    .findings_by_id
                    .get_mut(&finding_id)
                    .ok_or_else(ApiError::internal)?;
                finding.last_seen_at = now;
                finding.evidence = draft.evidence;

                if finding.status == FindingStatus::Remediated {
                    finding.status = FindingStatus::Reopened;
                }

                finding.clone()
            } else {
                let finding = Finding {
                    id: Uuid::now_v7(),
                    organization_id,
                    asset_id: scan_result.asset_id,
                    rule_id: draft.rule_id.clone(),
                    title: draft.title,
                    severity: draft.severity,
                    status: FindingStatus::Open,
                    confidence: draft.confidence,
                    evidence: draft.evidence,
                    remediation: draft.remediation,
                    first_seen_at: now,
                    last_seen_at: now,
                };

                repository.finding_ids_by_asset_rule.insert(key, finding.id);
                repository
                    .findings_by_id
                    .insert(finding.id, finding.clone());
                finding
            };

        if let Some(index) = response_indexes_by_finding_id.get(&finding.id).copied() {
            findings[index] = finding;
        } else {
            response_indexes_by_finding_id.insert(finding.id, findings.len());
            findings.push(finding);
        }
    }

    Ok(Json(DeriveFindingsResponse { findings }))
}

async fn list_findings(
    State(repository): State<Arc<Mutex<InMemoryRepository>>>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<Vec<Finding>>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let repository = repository.lock().map_err(|_| ApiError::internal())?;
    repository.require_membership(user_id, organization_id)?;

    let mut findings = repository
        .findings_by_id
        .values()
        .filter(|finding| finding.organization_id == organization_id)
        .cloned()
        .collect::<Vec<_>>();

    findings.sort_by(|left, right| right.last_seen_at.cmp(&left.last_seen_at));

    Ok(Json(findings))
}

async fn update_finding_status(
    State(repository): State<Arc<Mutex<InMemoryRepository>>>,
    headers: HeaderMap,
    Path((organization_id, finding_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<UpdateFindingStatusRequest>,
) -> Result<Json<UpdateFindingStatusResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let note = validate_optional_text(request.note, "note", 1_000)?;
    let mut repository = repository.lock().map_err(|_| ApiError::internal())?;
    repository.require_membership(user_id, organization_id)?;

    let finding = {
        let finding = repository
            .findings_by_id
            .get_mut(&finding_id)
            .ok_or_else(|| ApiError::not_found("finding does not exist"))?;

        if finding.organization_id != organization_id {
            return Err(ApiError::not_found(
                "finding does not belong to this organization",
            ));
        }

        finding.status = request.status;
        finding.clone()
    };

    let event = note.map(|note| {
        let event = FindingEvent {
            id: Uuid::now_v7(),
            organization_id,
            finding_id,
            actor_user_id: user_id,
            event_type: format!("status_changed_to_{}", finding_status_slug(request.status)),
            note: Some(note),
            created_at: Utc::now(),
        };
        repository
            .finding_events_by_id
            .insert(event.id, event.clone());
        event
    });

    Ok(Json(UpdateFindingStatusResponse { finding, event }))
}

async fn create_finding_note(
    State(repository): State<Arc<Mutex<InMemoryRepository>>>,
    headers: HeaderMap,
    Path((organization_id, finding_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<CreateFindingNoteRequest>,
) -> Result<Json<CreateFindingNoteResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let note = validate_required_note(&request.note)?;
    let mut repository = repository.lock().map_err(|_| ApiError::internal())?;
    repository.require_membership(user_id, organization_id)?;

    let finding = repository
        .findings_by_id
        .get(&finding_id)
        .ok_or_else(|| ApiError::not_found("finding does not exist"))?;

    if finding.organization_id != organization_id {
        return Err(ApiError::not_found(
            "finding does not belong to this organization",
        ));
    }

    let event = FindingEvent {
        id: Uuid::now_v7(),
        organization_id,
        finding_id,
        actor_user_id: user_id,
        event_type: "note_added".to_string(),
        note: Some(note),
        created_at: Utc::now(),
    };

    repository
        .finding_events_by_id
        .insert(event.id, event.clone());

    Ok(Json(CreateFindingNoteResponse { event }))
}

async fn list_finding_notes(
    State(repository): State<Arc<Mutex<InMemoryRepository>>>,
    headers: HeaderMap,
    Path((organization_id, finding_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Vec<FindingEvent>>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let repository = repository.lock().map_err(|_| ApiError::internal())?;
    repository.require_membership(user_id, organization_id)?;

    let finding = repository
        .findings_by_id
        .get(&finding_id)
        .ok_or_else(|| ApiError::not_found("finding does not exist"))?;

    if finding.organization_id != organization_id {
        return Err(ApiError::not_found(
            "finding does not belong to this organization",
        ));
    }

    let mut events = repository
        .finding_events_by_id
        .values()
        .filter(|event| event.organization_id == organization_id && event.finding_id == finding_id)
        .cloned()
        .collect::<Vec<_>>();

    events.sort_by(|left, right| right.created_at.cmp(&left.created_at));

    Ok(Json(events))
}

async fn create_slack_channel(
    State(repository): State<Arc<Mutex<InMemoryRepository>>>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
    Json(request): Json<CreateSlackChannelRequest>,
) -> Result<Json<CreateSlackChannelResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let name = validate_channel_name(&request.name)?;
    let webhook_url = validate_slack_webhook_url(&request.webhook_url)?;
    let mut repository = repository.lock().map_err(|_| ApiError::internal())?;
    let role = repository.require_membership(user_id, organization_id)?;

    if !matches!(role, MemberRole::Owner | MemberRole::Admin) {
        return Err(ApiError::forbidden(
            "only organization owners and admins can configure Slack channels",
        ));
    }

    let channel = SlackNotificationChannel {
        id: Uuid::now_v7(),
        organization_id,
        name,
        enabled: true,
        created_at: Utc::now(),
    };

    repository
        .slack_secret_refs_by_id
        .insert(channel.id, webhook_url);
    repository
        .slack_channels_by_id
        .insert(channel.id, channel.clone());

    Ok(Json(CreateSlackChannelResponse { channel }))
}

async fn queue_slack_alert(
    State(repository): State<Arc<Mutex<InMemoryRepository>>>,
    headers: HeaderMap,
    Path((organization_id, finding_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<QueueSlackAlertResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let mut repository = repository.lock().map_err(|_| ApiError::internal())?;
    repository.require_membership(user_id, organization_id)?;

    let finding = repository
        .findings_by_id
        .get(&finding_id)
        .ok_or_else(|| ApiError::not_found("finding does not exist"))?
        .clone();

    if finding.organization_id != organization_id {
        return Err(ApiError::not_found(
            "finding does not belong to this organization",
        ));
    }

    let channel = repository
        .slack_channels_by_id
        .values()
        .find(|channel| channel.organization_id == organization_id && channel.enabled)
        .cloned()
        .ok_or_else(|| ApiError::conflict("no enabled Slack channel is configured"))?;

    let asset_domain = repository
        .domain_assets_by_id
        .get(&finding.asset_id)
        .map(|asset| asset.domain.as_str())
        .unwrap_or("unknown-domain");
    let payload = build_slack_finding_alert(&finding, asset_domain).text;

    let alert = Alert {
        id: Uuid::now_v7(),
        organization_id,
        finding_id,
        notification_channel_id: channel.id,
        status: AlertStatus::Queued,
        payload,
        created_at: Utc::now(),
        sent_at: None,
    };

    repository.alerts_by_id.insert(alert.id, alert.clone());

    Ok(Json(QueueSlackAlertResponse { alert }))
}

async fn list_alerts(
    State(repository): State<Arc<Mutex<InMemoryRepository>>>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<Vec<Alert>>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let repository = repository.lock().map_err(|_| ApiError::internal())?;
    repository.require_membership(user_id, organization_id)?;

    let mut alerts = repository
        .alerts_by_id
        .values()
        .filter(|alert| alert.organization_id == organization_id)
        .cloned()
        .collect::<Vec<_>>();

    alerts.sort_by(|left, right| right.created_at.cmp(&left.created_at));

    Ok(Json(alerts))
}

async fn create_remediation_task(
    State(repository): State<Arc<Mutex<InMemoryRepository>>>,
    headers: HeaderMap,
    Path((organization_id, finding_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<CreateRemediationTaskRequest>,
) -> Result<Json<CreateRemediationTaskResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let mut repository = repository.lock().map_err(|_| ApiError::internal())?;
    repository.require_membership(user_id, organization_id)?;

    let finding = repository
        .findings_by_id
        .get(&finding_id)
        .ok_or_else(|| ApiError::not_found("finding does not exist"))?
        .clone();

    if finding.organization_id != organization_id {
        return Err(ApiError::not_found(
            "finding does not belong to this organization",
        ));
    }

    let title = validate_task_title(
        request
            .title
            .unwrap_or_else(|| format!("Remediate: {}", finding.title)),
    )?;
    let assignee = validate_optional_text(request.assignee, "assignee", 120)?;
    let now = Utc::now();
    let task = RemediationTask {
        id: Uuid::now_v7(),
        organization_id,
        finding_id,
        title,
        status: RemediationStatus::Open,
        assignee,
        created_at: now,
        updated_at: now,
    };

    repository
        .remediation_tasks_by_id
        .insert(task.id, task.clone());

    Ok(Json(CreateRemediationTaskResponse { task }))
}

async fn list_remediation_tasks(
    State(repository): State<Arc<Mutex<InMemoryRepository>>>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<Vec<RemediationTask>>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let repository = repository.lock().map_err(|_| ApiError::internal())?;
    repository.require_membership(user_id, organization_id)?;

    let mut tasks = repository
        .remediation_tasks_by_id
        .values()
        .filter(|task| task.organization_id == organization_id)
        .cloned()
        .collect::<Vec<_>>();

    tasks.sort_by(|left, right| right.updated_at.cmp(&left.updated_at));

    Ok(Json(tasks))
}

async fn update_remediation_status(
    State(repository): State<Arc<Mutex<InMemoryRepository>>>,
    headers: HeaderMap,
    Path((organization_id, task_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<UpdateRemediationStatusRequest>,
) -> Result<Json<UpdateRemediationStatusResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let mut repository = repository.lock().map_err(|_| ApiError::internal())?;
    repository.require_membership(user_id, organization_id)?;

    let (finding_id, task) = {
        let task = repository
            .remediation_tasks_by_id
            .get_mut(&task_id)
            .ok_or_else(|| ApiError::not_found("remediation task does not exist"))?;

        if task.organization_id != organization_id {
            return Err(ApiError::not_found(
                "remediation task does not belong to this organization",
            ));
        }

        task.status = request.status;
        task.updated_at = Utc::now();
        (task.finding_id, task.clone())
    };

    if let Some(finding) = repository.findings_by_id.get_mut(&finding_id) {
        finding.status = match request.status {
            RemediationStatus::Open => FindingStatus::Open,
            RemediationStatus::InProgress | RemediationStatus::Blocked => FindingStatus::InProgress,
            RemediationStatus::Remediated => FindingStatus::Remediated,
            RemediationStatus::AcceptedRisk => FindingStatus::AcceptedRisk,
            RemediationStatus::FalsePositive => FindingStatus::FalsePositive,
        };
    }

    Ok(Json(UpdateRemediationStatusResponse { task }))
}

fn normalize_email(input: &str) -> Result<String, ApiError> {
    let email = input.trim().to_ascii_lowercase();

    if email.len() < 6 || !email.contains('@') || !email.contains('.') {
        return Err(ApiError::bad_request("email must be a valid address"));
    }

    Ok(email)
}

fn validate_display_name(input: &str) -> Result<String, ApiError> {
    let display_name = input.trim();

    if display_name.len() < 2 {
        return Err(ApiError::bad_request(
            "display name must be at least 2 characters",
        ));
    }

    Ok(display_name.to_string())
}

fn validate_organization_name(input: &str) -> Result<String, ApiError> {
    let name = input.trim();

    if name.len() < 2 {
        return Err(ApiError::bad_request(
            "organization name must be at least 2 characters",
        ));
    }

    Ok(name.to_string())
}

fn validate_channel_name(input: &str) -> Result<String, ApiError> {
    let name = input.trim();

    if name.len() < 2 || name.len() > 80 {
        return Err(ApiError::bad_request(
            "channel name must be between 2 and 80 characters",
        ));
    }

    Ok(name.to_string())
}

fn validate_slack_webhook_url(input: &str) -> Result<String, ApiError> {
    let webhook_url = input.trim();

    if !webhook_url.starts_with("https://hooks.slack.com/") {
        return Err(ApiError::bad_request(
            "Slack webhook URL must start with https://hooks.slack.com/",
        ));
    }

    Ok(webhook_url.to_string())
}

fn validate_task_title(input: String) -> Result<String, ApiError> {
    let title = input.trim();

    if title.len() < 3 || title.len() > 160 {
        return Err(ApiError::bad_request(
            "task title must be between 3 and 160 characters",
        ));
    }

    Ok(title.to_string())
}

fn validate_required_note(input: &str) -> Result<String, ApiError> {
    let note = input.trim();

    if note.len() < 3 || note.len() > 1_000 {
        return Err(ApiError::bad_request(
            "note must be between 3 and 1000 characters",
        ));
    }

    Ok(note.to_string())
}

fn validate_optional_text(
    input: Option<String>,
    field_name: &str,
    max_len: usize,
) -> Result<Option<String>, ApiError> {
    let Some(value) = input else {
        return Ok(None);
    };
    let value = value.trim();

    if value.is_empty() {
        return Ok(None);
    }

    if value.len() > max_len {
        return Err(ApiError::bad_request(format!(
            "{field_name} must be {max_len} characters or fewer",
        )));
    }

    Ok(Some(value.to_string()))
}

fn finding_status_slug(status: FindingStatus) -> &'static str {
    match status {
        FindingStatus::Open => "open",
        FindingStatus::AcceptedRisk => "accepted_risk",
        FindingStatus::FalsePositive => "false_positive",
        FindingStatus::InProgress => "in_progress",
        FindingStatus::Remediated => "remediated",
        FindingStatus::Reopened => "reopened",
    }
}

fn validate_scan_reason(input: Option<String>) -> Result<Option<String>, ApiError> {
    let Some(reason) = input else {
        return Ok(None);
    };
    let reason = reason.trim();

    if reason.is_empty() {
        return Ok(None);
    }

    if reason.len() > 240 {
        return Err(ApiError::bad_request(
            "scan reason must be 240 characters or fewer",
        ));
    }

    Ok(Some(reason.to_string()))
}

fn session_for_user(user_id: Uuid) -> Result<SessionToken, ApiError> {
    const SESSION_TTL_SECONDS: i64 = 60 * 60 * 8;
    let access_token =
        issue_session_token(user_id, session_secret().as_bytes(), SESSION_TTL_SECONDS)
            .map_err(|_| ApiError::internal())?;

    Ok(SessionToken {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in_seconds: SESSION_TTL_SECONDS,
    })
}

fn session_secret() -> String {
    std::env::var("CEEM_SESSION_SECRET")
        .unwrap_or_else(|_| "dev-only-change-me-before-production".to_string())
}

fn current_user_id(headers: &HeaderMap) -> Result<Uuid, ApiError> {
    if let Some(value) = headers.get("authorization") {
        let value = value
            .to_str()
            .map_err(|_| ApiError::unauthorized("authorization header must be valid UTF-8"))?;
        let Some(token) = value.strip_prefix("Bearer ") else {
            return Err(ApiError::unauthorized(
                "authorization header must use Bearer token",
            ));
        };

        return verify_session_token(token, session_secret().as_bytes())
            .map_err(|_| ApiError::unauthorized("session token is invalid or expired"));
    }

    let value = headers
        .get("x-ceem-user-id")
        .ok_or_else(|| ApiError::unauthorized("x-ceem-user-id header is required"))?;
    let value = value
        .to_str()
        .map_err(|_| ApiError::unauthorized("x-ceem-user-id must be a UUID"))?;

    Uuid::parse_str(value).map_err(|_| ApiError::unauthorized("x-ceem-user-id must be a UUID"))
}

impl InMemoryRepository {
    fn require_membership(
        &self,
        user_id: Uuid,
        organization_id: Uuid,
    ) -> Result<MemberRole, ApiError> {
        if !self.users_by_id.contains_key(&user_id) {
            return Err(ApiError::unauthorized("user does not exist"));
        }

        if !self.organizations_by_id.contains_key(&organization_id) {
            return Err(ApiError::not_found("organization does not exist"));
        }

        self.memberships
            .iter()
            .find(|membership| {
                membership.user_id == user_id && membership.organization_id == organization_id
            })
            .map(|membership| membership.role)
            .ok_or_else(|| ApiError::forbidden("user is not a member of this organization"))
    }
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
        }
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }

    fn bad_gateway(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            message: message.into(),
        }
    }

    fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "internal server error".to_string(),
        }
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_email() {
        assert_eq!(
            normalize_email(" Person@Example.COM ").unwrap(),
            "person@example.com"
        );
    }

    #[test]
    fn rejects_invalid_email() {
        assert!(normalize_email("person").is_err());
    }

    #[test]
    fn validates_organization_name() {
        assert_eq!(validate_organization_name(" Acme ").unwrap(), "Acme");
    }

    #[test]
    fn denies_non_membership() {
        let repository = InMemoryRepository::default();

        assert_eq!(
            repository
                .require_membership(Uuid::now_v7(), Uuid::now_v7())
                .unwrap_err()
                .status,
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn trims_scan_reason() {
        assert_eq!(
            validate_scan_reason(Some(" certificate rotation ".to_string())).unwrap(),
            Some("certificate rotation".to_string())
        );
    }

    #[test]
    fn rejects_long_scan_reason() {
        assert!(validate_scan_reason(Some("x".repeat(241))).is_err());
    }

    #[test]
    fn validates_required_note() {
        assert_eq!(
            validate_required_note(" accepted for launch week ").unwrap(),
            "accepted for launch week"
        );
    }

    #[test]
    fn exposes_finding_status_slugs() {
        assert_eq!(
            finding_status_slug(FindingStatus::AcceptedRisk),
            "accepted_risk"
        );
    }
}
