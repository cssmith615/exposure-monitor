use std::{
    collections::{HashMap, VecDeque},
    sync::{Mutex, OnceLock},
};

use axum::{
    Json, Router,
    extract::{FromRef, Path, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use ceem_alerts::{build_slack_finding_alert, deliver_slack_message};
use ceem_auth::{
    PasswordPolicy, hash_password, issue_session_token, validate_password_policy, verify_password,
    verify_session_token,
};
use ceem_db::{DatabaseConfig, PostgresRepository};
use ceem_findings::derive_findings_from_scan_result;
use ceem_scanner::{collect_dns_policy_baseline, probe_http_endpoint, resolve_dns_baseline};
use ceem_shared::{
    AcceptOrganizationInviteResponse, Alert, AlertStatus, AuditLog, Confidence,
    CreateDomainAssetRequest, CreateDomainAssetResponse, CreateFindingNoteRequest,
    CreateFindingNoteResponse, CreateOrganizationInviteRequest, CreateOrganizationInviteResponse,
    CreateOrganizationRequest, CreateOrganizationResponse, CreateRemediationTaskRequest,
    CreateRemediationTaskResponse, CreateScanJobRequest, CreateScanJobResponse,
    CreateScheduledScanRequest, CreateSlackChannelRequest, CreateSlackChannelResponse,
    DeriveFindingsResponse, DomainAsset, Finding, FindingEvent, FindingStatus, HealthResponse,
    LoginRequest, LoginResponse, MemberRole, Organization, OrganizationInvite, OrganizationMember,
    OrganizationMembership, OrganizationSummary, PRODUCT_NAME, QueueSlackAlertResponse,
    RegisterUserRequest, RegisterUserResponse, RemediationStatus, RemediationTask,
    RunDnsBaselineScanResponse, ScanCadence, ScanEvidence, ScanJob, ScanProfile, ScanResult,
    ScanStatus, ScheduledScan, ScheduledScanResponse, ServiceStatus, SessionToken, Severity,
    SlackNotificationChannel, UpdateFindingStatusRequest, UpdateFindingStatusResponse,
    UpdateMemberRoleRequest, UpdateMemberRoleResponse, UpdateRemediationStatusRequest,
    UpdateRemediationStatusResponse, UpdateScheduledScanRequest, UserAccount,
    calculate_finding_risk_score, finding_risk_factors, validate_domain, validate_slug,
};
use chrono::{Duration, Utc};
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::{PgPool, Row, postgres::PgRow};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let repository = PostgresRepository::connect(&DatabaseConfig::from_env()?).await?;
    repository.migrate().await?;

    let bind_addr =
        std::env::var("CEEM_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    info!(%bind_addr, "starting CEEM API");

    axum::serve(listener, app(repository.pool().clone())).await?;
    Ok(())
}

fn app(pool: PgPool) -> Router {
    let state = AppState { pool };

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
            "/v1/organizations/{organization_id}/scheduled-scans",
            get(list_scheduled_scans),
        )
        .route(
            "/v1/organizations/{organization_id}/domain-assets/{asset_id}/scheduled-scans",
            post(create_scheduled_scan),
        )
        .route(
            "/v1/organizations/{organization_id}/scheduled-scans/{scheduled_scan_id}",
            post(update_scheduled_scan),
        )
        .route(
            "/v1/organizations/{organization_id}/scheduled-scans/{scheduled_scan_id}/pause",
            post(pause_scheduled_scan),
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
            "/v1/organizations/{organization_id}/alerts/{alert_id}/deliver",
            post(deliver_alert),
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
        .route(
            "/v1/organizations/{organization_id}/audit-logs",
            get(list_audit_logs),
        )
        .with_state(state)
        .layer(cors_layer())
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

fn cors_layer() -> CorsLayer {
    let methods = [Method::GET, Method::POST, Method::OPTIONS];
    if let Ok(origin) = std::env::var("CEEM_CORS_ORIGIN")
        && let Ok(origin) = HeaderValue::from_str(&origin)
    {
        return CorsLayer::new()
            .allow_origin(origin)
            .allow_methods(methods)
            .allow_headers(Any);
    }

    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(methods)
        .allow_headers(Any)
}

#[derive(Clone)]
struct AppState {
    pool: PgPool,
}

impl FromRef<AppState> for PgPool {
    fn from_ref(state: &AppState) -> Self {
        state.pool.clone()
    }
}

async fn register_user(
    State(pool): State<PgPool>,
    Json(request): Json<RegisterUserRequest>,
) -> Result<Json<RegisterUserResponse>, ApiError> {
    let email = normalize_email(&request.email)?;
    enforce_auth_rate_limit(&email)?;
    let display_name = validate_display_name(&request.display_name)?;
    validate_password_policy(&request.password, &PasswordPolicy::default())
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let password_hash = hash_password(&request.password).map_err(|_| ApiError::internal())?;

    if find_user_by_email(&pool, &email).await?.is_some() {
        return Err(ApiError::conflict("email is already registered"));
    }

    let row = sqlx::query(
        r#"
        INSERT INTO users (id, email, display_name, password_hash)
        VALUES ($1, $2, $3, $4)
        RETURNING id, email, display_name, created_at
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(email)
    .bind(display_name)
    .bind(password_hash)
    .fetch_one(&pool)
    .await
    .map_err(map_sql_error)?;

    let user = user_from_row(&row);
    let session = session_for_user(user.id)?;
    record_audit(
        &pool,
        None,
        Some(user.id),
        "auth.registered",
        "user",
        Some(user.id),
        json!({ "email": user.email }),
    )
    .await?;

    Ok(Json(RegisterUserResponse { user, session }))
}

async fn login_user(
    State(pool): State<PgPool>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let email = normalize_email(&request.email)?;
    enforce_auth_rate_limit(&email)?;
    let (user, password_hash) = find_user_by_email(&pool, &email)
        .await?
        .ok_or_else(|| ApiError::unauthorized("email or password is incorrect"))?;

    if !verify_password(&request.password, &password_hash).map_err(|_| ApiError::internal())? {
        return Err(ApiError::unauthorized("email or password is incorrect"));
    }

    let session = session_for_user(user.id)?;
    record_audit(
        &pool,
        None,
        Some(user.id),
        "auth.login",
        "user",
        Some(user.id),
        json!({ "email": user.email }),
    )
    .await?;

    Ok(Json(LoginResponse { user, session }))
}

async fn create_organization(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(request): Json<CreateOrganizationRequest>,
) -> Result<Json<CreateOrganizationResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;
    require_user(&pool, user_id).await?;
    let name = validate_organization_name(&request.name)?;
    let slug =
        validate_slug(&request.slug).map_err(|error| ApiError::bad_request(error.to_string()))?;

    if organization_by_slug(&pool, &slug).await?.is_some() {
        return Err(ApiError::conflict("organization slug is already taken"));
    }

    let mut transaction = pool.begin().await.map_err(map_sql_error)?;
    let organization_row = sqlx::query(
        r#"
        INSERT INTO organizations (id, name, slug)
        VALUES ($1, $2, $3)
        RETURNING id, name, slug, created_at
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(name)
    .bind(slug)
    .fetch_one(&mut *transaction)
    .await
    .map_err(map_sql_error)?;
    let organization = organization_from_row(&organization_row);
    let membership_row = sqlx::query(
        r#"
        INSERT INTO organization_members (organization_id, user_id, role)
        VALUES ($1, $2, $3::member_role)
        RETURNING organization_id, user_id, role::text AS role, created_at
        "#,
    )
    .bind(organization.id)
    .bind(user_id)
    .bind(member_role_slug(MemberRole::Owner))
    .fetch_one(&mut *transaction)
    .await
    .map_err(map_sql_error)?;
    transaction.commit().await.map_err(map_sql_error)?;

    Ok(Json(CreateOrganizationResponse {
        organization,
        membership: membership_from_row(&membership_row),
    }))
}

async fn list_organizations(
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<Json<Vec<OrganizationSummary>>, ApiError> {
    let user_id = current_user_id(&headers)?;
    require_user(&pool, user_id).await?;
    let rows = sqlx::query(
        r#"
        SELECT
            organizations.id,
            organizations.name,
            organizations.slug,
            organizations.created_at,
            organization_members.role::text AS role
        FROM organization_members
        INNER JOIN organizations ON organizations.id = organization_members.organization_id
        WHERE organization_members.user_id = $1
        ORDER BY organizations.name ASC
        "#,
    )
    .bind(user_id)
    .fetch_all(&pool)
    .await
    .map_err(map_sql_error)?;

    Ok(Json(
        rows.iter()
            .map(|row| OrganizationSummary {
                organization: organization_from_row(row),
                role: parse_member_role(row.get("role")),
            })
            .collect(),
    ))
}

async fn list_organization_members(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<Vec<OrganizationMember>>, ApiError> {
    let user_id = current_user_id(&headers)?;
    require_membership(&pool, user_id, organization_id).await?;
    Ok(Json(list_members(&pool, organization_id).await?))
}

async fn create_organization_invite(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
    Json(request): Json<CreateOrganizationInviteRequest>,
) -> Result<Json<CreateOrganizationInviteResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let role = require_membership(&pool, user_id, organization_id).await?;
    if !matches!(role, MemberRole::Owner | MemberRole::Admin) {
        return Err(ApiError::forbidden(
            "only organization owners and admins can invite members",
        ));
    }
    if matches!(request.role, MemberRole::Owner) && !matches!(role, MemberRole::Owner) {
        return Err(ApiError::forbidden("only owners can invite another owner"));
    }

    let email = normalize_email(&request.email)?;
    let token = Uuid::now_v7().to_string();
    let row = sqlx::query(
        r#"
        INSERT INTO organization_invites
            (id, organization_id, email, role, token_hash, invited_by)
        VALUES ($1, $2, $3, $4::member_role, $5, $6)
        RETURNING id, organization_id, email, role::text AS role, token_hash, invited_by,
            accepted_at, created_at
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(organization_id)
    .bind(email)
    .bind(member_role_slug(request.role))
    .bind(&token)
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .map_err(map_sql_error)?;

    let mut invite = invite_from_row(&row);
    invite.token = token;
    record_audit(
        &pool,
        Some(organization_id),
        Some(user_id),
        "organization.invite_created",
        "organization_invite",
        Some(invite.id),
        json!({ "email": invite.email, "role": member_role_slug(invite.role) }),
    )
    .await?;

    Ok(Json(CreateOrganizationInviteResponse { invite }))
}

async fn accept_organization_invite(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Result<Json<AcceptOrganizationInviteResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let user = require_user(&pool, user_id).await?;
    let row = sqlx::query(
        r#"
        SELECT id, organization_id, email, role::text AS role, token_hash, invited_by,
            accepted_at, created_at
        FROM organization_invites
        WHERE token_hash = $1
        "#,
    )
    .bind(&token)
    .fetch_optional(&pool)
    .await
    .map_err(map_sql_error)?
    .ok_or_else(|| ApiError::not_found("organization invite does not exist"))?;
    let invite = invite_from_row(&row);

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

    let mut transaction = pool.begin().await.map_err(map_sql_error)?;
    sqlx::query("UPDATE organization_invites SET accepted_at = now() WHERE id = $1")
        .bind(invite.id)
        .execute(&mut *transaction)
        .await
        .map_err(map_sql_error)?;
    let membership_row = sqlx::query(
        r#"
        INSERT INTO organization_members (organization_id, user_id, role)
        VALUES ($1, $2, $3::member_role)
        ON CONFLICT (organization_id, user_id)
        DO UPDATE SET role = EXCLUDED.role
        RETURNING organization_id, user_id, role::text AS role, created_at
        "#,
    )
    .bind(invite.organization_id)
    .bind(user_id)
    .bind(member_role_slug(invite.role))
    .fetch_one(&mut *transaction)
    .await
    .map_err(map_sql_error)?;
    transaction.commit().await.map_err(map_sql_error)?;

    let organization = organization_by_id(&pool, invite.organization_id)
        .await?
        .ok_or_else(ApiError::internal)?;

    record_audit(
        &pool,
        Some(invite.organization_id),
        Some(user_id),
        "organization.invite_accepted",
        "organization_invite",
        Some(invite.id),
        json!({}),
    )
    .await?;

    Ok(Json(AcceptOrganizationInviteResponse {
        organization,
        membership: membership_from_row(&membership_row),
    }))
}

async fn update_member_role(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path((organization_id, member_user_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<UpdateMemberRoleRequest>,
) -> Result<Json<UpdateMemberRoleResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let actor_role = require_membership(&pool, user_id, organization_id).await?;
    if !matches!(actor_role, MemberRole::Owner | MemberRole::Admin) {
        return Err(ApiError::forbidden(
            "only organization owners and admins can update member roles",
        ));
    }
    if matches!(request.role, MemberRole::Owner) && !matches!(actor_role, MemberRole::Owner) {
        return Err(ApiError::forbidden("only owners can assign owner role"));
    }

    let row = sqlx::query(
        r#"
        UPDATE organization_members
        SET role = $3::member_role
        WHERE organization_id = $1 AND user_id = $2
        RETURNING organization_id, user_id, role::text AS role, created_at
        "#,
    )
    .bind(organization_id)
    .bind(member_user_id)
    .bind(member_role_slug(request.role))
    .fetch_optional(&pool)
    .await
    .map_err(map_sql_error)?
    .ok_or_else(|| ApiError::not_found("organization member does not exist"))?;

    record_audit(
        &pool,
        Some(organization_id),
        Some(user_id),
        "organization.member_role_updated",
        "user",
        Some(member_user_id),
        json!({ "role": member_role_slug(request.role) }),
    )
    .await?;

    Ok(Json(UpdateMemberRoleResponse {
        membership: membership_from_row(&row),
    }))
}

async fn create_domain_asset(
    State(pool): State<PgPool>,
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
    let role = require_membership(&pool, user_id, organization_id).await?;
    if !matches!(role, MemberRole::Owner | MemberRole::Admin) {
        return Err(ApiError::forbidden(
            "only organization owners and admins can add monitored domains",
        ));
    }
    let domain = validate_domain(&request.domain)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;

    let row = sqlx::query(
        r#"
        INSERT INTO assets
            (id, organization_id, kind, value, authorization_attested_by, authorization_attested_at)
        VALUES ($1, $2, 'domain', $3, $4, now())
        RETURNING id, organization_id, value, authorization_attested_by,
            authorization_attested_at, created_at
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(organization_id)
    .bind(domain)
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .map_err(map_sql_error)?;
    let asset = domain_asset_from_row(&row);

    record_audit(
        &pool,
        Some(organization_id),
        Some(user_id),
        "domain.added",
        "domain_asset",
        Some(asset.id),
        json!({ "domain": asset.domain }),
    )
    .await?;

    Ok(Json(CreateDomainAssetResponse { asset }))
}

async fn list_domain_assets(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<Vec<DomainAsset>>, ApiError> {
    let user_id = current_user_id(&headers)?;
    require_membership(&pool, user_id, organization_id).await?;
    let rows = sqlx::query(
        r#"
        SELECT id, organization_id, value, authorization_attested_by,
            authorization_attested_at, created_at
        FROM assets
        WHERE organization_id = $1 AND kind = 'domain'
        ORDER BY value ASC
        "#,
    )
    .bind(organization_id)
    .fetch_all(&pool)
    .await
    .map_err(map_sql_error)?;

    Ok(Json(rows.iter().map(domain_asset_from_row).collect()))
}

async fn create_scan_job(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path((organization_id, asset_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<CreateScanJobRequest>,
) -> Result<Json<CreateScanJobResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let role = require_membership(&pool, user_id, organization_id).await?;
    if matches!(role, MemberRole::Viewer) {
        return Err(ApiError::forbidden(
            "viewers cannot trigger external exposure scans",
        ));
    }
    require_asset_in_org(&pool, organization_id, asset_id).await?;
    let reason = validate_scan_reason(request.reason)?;

    let row = sqlx::query(
        r#"
        INSERT INTO scan_jobs (id, organization_id, requested_by, asset_id, reason, scan_type)
        VALUES ($1, $2, $3, $4, $5, 'dns_baseline')
        RETURNING id, organization_id, asset_id, requested_by, status::text AS status, reason,
            created_at, started_at, completed_at
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(organization_id)
    .bind(user_id)
    .bind(asset_id)
    .bind(reason)
    .fetch_one(&pool)
    .await
    .map_err(map_sql_error)?;
    let scan_job = scan_job_from_row(&row);

    record_audit(
        &pool,
        Some(organization_id),
        Some(user_id),
        "scan.queued",
        "scan_job",
        Some(scan_job.id),
        json!({ "asset_id": asset_id, "reason": scan_job.reason }),
    )
    .await?;

    Ok(Json(CreateScanJobResponse { scan_job }))
}

async fn list_scan_jobs(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<Vec<ScanJob>>, ApiError> {
    let user_id = current_user_id(&headers)?;
    require_membership(&pool, user_id, organization_id).await?;
    let rows = sqlx::query(
        r#"
        SELECT id, organization_id, asset_id, requested_by, status::text AS status, reason,
            created_at, started_at, completed_at
        FROM scan_jobs
        WHERE organization_id = $1
        ORDER BY created_at DESC
        "#,
    )
    .bind(organization_id)
    .fetch_all(&pool)
    .await
    .map_err(map_sql_error)?;

    Ok(Json(rows.iter().map(scan_job_from_row).collect()))
}

async fn list_scheduled_scans(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<Vec<ScheduledScan>>, ApiError> {
    let user_id = current_user_id(&headers)?;
    require_membership(&pool, user_id, organization_id).await?;
    let rows = sqlx::query(
        r#"
        SELECT id, organization_id, asset_id, cadence::text AS cadence, profile::text AS profile,
            enabled, next_run_at, last_enqueued_at, created_by, created_at, updated_at
        FROM scheduled_scans
        WHERE organization_id = $1
        ORDER BY enabled DESC, next_run_at ASC NULLS LAST, updated_at DESC
        "#,
    )
    .bind(organization_id)
    .fetch_all(&pool)
    .await
    .map_err(map_sql_error)?;

    Ok(Json(rows.iter().map(scheduled_scan_from_row).collect()))
}

async fn create_scheduled_scan(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path((organization_id, asset_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<CreateScheduledScanRequest>,
) -> Result<Json<ScheduledScanResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let role = require_membership(&pool, user_id, organization_id).await?;
    if matches!(role, MemberRole::Viewer) {
        return Err(ApiError::forbidden(
            "viewers cannot configure scan schedules",
        ));
    }
    require_asset_in_org(&pool, organization_id, asset_id).await?;
    let next_run_at = next_run_for_cadence(request.cadence);
    let row = sqlx::query(
        r#"
        INSERT INTO scheduled_scans (
            id, organization_id, asset_id, cadence, profile, enabled, next_run_at, created_by
        )
        VALUES ($1, $2, $3, $4::scan_cadence, $5::scan_profile, true, $6, $7)
        ON CONFLICT (asset_id, profile)
        DO UPDATE SET
            cadence = EXCLUDED.cadence,
            enabled = true,
            next_run_at = EXCLUDED.next_run_at,
            updated_at = now()
        RETURNING id, organization_id, asset_id, cadence::text AS cadence, profile::text AS profile,
            enabled, next_run_at, last_enqueued_at, created_by, created_at, updated_at
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(organization_id)
    .bind(asset_id)
    .bind(scan_cadence_slug(request.cadence))
    .bind(scan_profile_slug(request.profile))
    .bind(next_run_at)
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .map_err(map_sql_error)?;
    let scheduled_scan = scheduled_scan_from_row(&row);
    record_audit(
        &pool,
        Some(organization_id),
        Some(user_id),
        "scheduled_scan.upserted",
        "scheduled_scan",
        Some(scheduled_scan.id),
        json!({
            "asset_id": asset_id,
            "cadence": scan_cadence_slug(scheduled_scan.cadence),
            "profile": scan_profile_slug(scheduled_scan.profile)
        }),
    )
    .await?;

    Ok(Json(ScheduledScanResponse { scheduled_scan }))
}

async fn update_scheduled_scan(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path((organization_id, scheduled_scan_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<UpdateScheduledScanRequest>,
) -> Result<Json<ScheduledScanResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let role = require_membership(&pool, user_id, organization_id).await?;
    if matches!(role, MemberRole::Viewer) {
        return Err(ApiError::forbidden("viewers cannot update scan schedules"));
    }
    let next_run_at = if request.enabled {
        next_run_for_cadence(request.cadence)
    } else {
        None
    };
    let row = sqlx::query(
        r#"
        UPDATE scheduled_scans
        SET cadence = $3::scan_cadence,
            profile = $4::scan_profile,
            enabled = $5,
            next_run_at = $6,
            updated_at = now()
        WHERE id = $1 AND organization_id = $2
        RETURNING id, organization_id, asset_id, cadence::text AS cadence, profile::text AS profile,
            enabled, next_run_at, last_enqueued_at, created_by, created_at, updated_at
        "#,
    )
    .bind(scheduled_scan_id)
    .bind(organization_id)
    .bind(scan_cadence_slug(request.cadence))
    .bind(scan_profile_slug(request.profile))
    .bind(request.enabled)
    .bind(next_run_at)
    .fetch_optional(&pool)
    .await
    .map_err(map_sql_error)?
    .ok_or_else(|| ApiError::not_found("scheduled scan does not exist"))?;
    let scheduled_scan = scheduled_scan_from_row(&row);
    record_audit(
        &pool,
        Some(organization_id),
        Some(user_id),
        "scheduled_scan.updated",
        "scheduled_scan",
        Some(scheduled_scan.id),
        json!({
            "enabled": scheduled_scan.enabled,
            "cadence": scan_cadence_slug(scheduled_scan.cadence),
            "profile": scan_profile_slug(scheduled_scan.profile)
        }),
    )
    .await?;

    Ok(Json(ScheduledScanResponse { scheduled_scan }))
}

async fn pause_scheduled_scan(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path((organization_id, scheduled_scan_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ScheduledScanResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let role = require_membership(&pool, user_id, organization_id).await?;
    if matches!(role, MemberRole::Viewer) {
        return Err(ApiError::forbidden("viewers cannot pause scan schedules"));
    }
    let row = sqlx::query(
        r#"
        UPDATE scheduled_scans
        SET enabled = false, next_run_at = NULL, updated_at = now()
        WHERE id = $1 AND organization_id = $2
        RETURNING id, organization_id, asset_id, cadence::text AS cadence, profile::text AS profile,
            enabled, next_run_at, last_enqueued_at, created_by, created_at, updated_at
        "#,
    )
    .bind(scheduled_scan_id)
    .bind(organization_id)
    .fetch_optional(&pool)
    .await
    .map_err(map_sql_error)?
    .ok_or_else(|| ApiError::not_found("scheduled scan does not exist"))?;
    let scheduled_scan = scheduled_scan_from_row(&row);
    record_audit(
        &pool,
        Some(organization_id),
        Some(user_id),
        "scheduled_scan.paused",
        "scheduled_scan",
        Some(scheduled_scan.id),
        json!({}),
    )
    .await?;

    Ok(Json(ScheduledScanResponse { scheduled_scan }))
}

async fn run_dns_baseline_scan(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path((organization_id, scan_job_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<RunDnsBaselineScanResponse>, ApiError> {
    run_scan_now(pool, headers, organization_id, scan_job_id, "dns_baseline").await
}

async fn run_http_probe_scan(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path((organization_id, scan_job_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<RunDnsBaselineScanResponse>, ApiError> {
    run_scan_now(pool, headers, organization_id, scan_job_id, "http_probe").await
}

async fn run_dns_policy_scan(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path((organization_id, scan_job_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<RunDnsBaselineScanResponse>, ApiError> {
    run_scan_now(pool, headers, organization_id, scan_job_id, "dns_policy").await
}

async fn run_scan_now(
    pool: PgPool,
    headers: HeaderMap,
    organization_id: Uuid,
    scan_job_id: Uuid,
    source: &str,
) -> Result<Json<RunDnsBaselineScanResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let (asset_id, domain) =
        claim_scan_job_asset(&pool, user_id, organization_id, scan_job_id, source).await?;
    let evidence = match source {
        "dns_baseline" => {
            ScanEvidence::DnsBaseline(resolve_dns_baseline(&domain).await.map_err(|error| {
                ApiError::bad_gateway(format!("DNS baseline scan failed: {error}"))
            })?)
        }
        "http_probe" => ScanEvidence::HttpProbe(
            probe_http_endpoint(&domain, "https")
                .await
                .map_err(|error| ApiError::bad_gateway(format!("HTTPS probe failed: {error}")))?,
        ),
        "dns_policy" => {
            ScanEvidence::DnsPolicy(collect_dns_policy_baseline(&domain).await.map_err(
                |error| ApiError::bad_gateway(format!("DNS policy scan failed: {error}")),
            )?)
        }
        _ => return Err(ApiError::bad_request("unsupported scan type")),
    };
    let scan_result = ScanResult {
        id: Uuid::now_v7(),
        organization_id,
        asset_id,
        scan_job_id,
        source: source.to_string(),
        observed_at: Utc::now(),
        evidence,
    };

    match complete_scan_job_with_result(&pool, scan_job_id, &scan_result).await {
        Ok(scan_job) => Ok(Json(RunDnsBaselineScanResponse {
            scan_job,
            scan_result,
        })),
        Err(error) => {
            mark_scan_job_failed(&pool, scan_job_id, error.message.clone()).await?;
            Err(error)
        }
    }
}

async fn list_scan_results(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<Vec<ScanResult>>, ApiError> {
    let user_id = current_user_id(&headers)?;
    require_membership(&pool, user_id, organization_id).await?;
    let rows = sqlx::query(
        r#"
        SELECT scan_results.id, scan_results.scan_job_id, scan_results.asset_id,
            scan_jobs.organization_id, scan_results.source, scan_results.observed_at,
            scan_results.evidence
        FROM scan_results
        INNER JOIN scan_jobs ON scan_jobs.id = scan_results.scan_job_id
        WHERE scan_jobs.organization_id = $1
        ORDER BY scan_results.observed_at DESC
        "#,
    )
    .bind(organization_id)
    .fetch_all(&pool)
    .await
    .map_err(map_sql_error)?;

    rows.iter()
        .map(scan_result_from_row)
        .collect::<Result<Vec<_>, _>>()
        .map(Json)
}

async fn derive_findings(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path((organization_id, scan_result_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<DeriveFindingsResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;
    require_membership(&pool, user_id, organization_id).await?;
    let scan_result = scan_result_by_id(&pool, organization_id, scan_result_id).await?;
    let findings = upsert_findings(&pool, &scan_result).await?;

    record_audit(
        &pool,
        Some(organization_id),
        Some(user_id),
        "finding.derived",
        "scan_result",
        Some(scan_result_id),
        json!({ "count": findings.len() }),
    )
    .await?;

    Ok(Json(DeriveFindingsResponse { findings }))
}

async fn list_findings(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<Vec<Finding>>, ApiError> {
    let user_id = current_user_id(&headers)?;
    require_membership(&pool, user_id, organization_id).await?;
    let rows = sqlx::query(
        r#"
        SELECT id, organization_id, asset_id, rule_id, title, severity::text AS severity,
            confidence::text AS confidence, status::text AS status, evidence, remediation,
            occurrence_count, risk_score, risk_factors, first_seen_at, last_seen_at
        FROM findings
        WHERE organization_id = $1
        ORDER BY risk_score DESC, last_seen_at DESC
        "#,
    )
    .bind(organization_id)
    .fetch_all(&pool)
    .await
    .map_err(map_sql_error)?;

    Ok(Json(rows.iter().map(finding_from_row).collect()))
}

async fn update_finding_status(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path((organization_id, finding_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<UpdateFindingStatusRequest>,
) -> Result<Json<UpdateFindingStatusResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;
    require_membership(&pool, user_id, organization_id).await?;
    let note = validate_optional_text(request.note, "note", 1_000)?;

    let row = sqlx::query(
        r#"
        UPDATE findings
        SET status = $3::finding_status,
            resolved_at = CASE
                WHEN $3 IN ('remediated', 'accepted_risk', 'false_positive') THEN now()
                ELSE NULL
            END
        WHERE id = $1 AND organization_id = $2
        RETURNING id, organization_id, asset_id, rule_id, title, severity::text AS severity,
            confidence::text AS confidence, status::text AS status, evidence, remediation,
            occurrence_count, risk_score, risk_factors, first_seen_at, last_seen_at
        "#,
    )
    .bind(finding_id)
    .bind(organization_id)
    .bind(finding_status_slug(request.status))
    .fetch_optional(&pool)
    .await
    .map_err(map_sql_error)?
    .ok_or_else(|| ApiError::not_found("finding does not exist"))?;
    let finding = finding_from_row(&row);
    let event = if note.is_some() {
        Some(
            insert_finding_event(
                &pool,
                organization_id,
                finding_id,
                user_id,
                "status_changed",
                note,
            )
            .await?,
        )
    } else {
        None
    };

    record_audit(
        &pool,
        Some(organization_id),
        Some(user_id),
        "finding.status_changed",
        "finding",
        Some(finding_id),
        json!({ "status": finding_status_slug(request.status) }),
    )
    .await?;

    Ok(Json(UpdateFindingStatusResponse { finding, event }))
}

async fn create_finding_note(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path((organization_id, finding_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<CreateFindingNoteRequest>,
) -> Result<Json<CreateFindingNoteResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;
    require_membership(&pool, user_id, organization_id).await?;
    require_finding_in_org(&pool, organization_id, finding_id).await?;
    let note = validate_required_note(&request.note)?;
    let event = insert_finding_event(
        &pool,
        organization_id,
        finding_id,
        user_id,
        "note_added",
        Some(note),
    )
    .await?;

    record_audit(
        &pool,
        Some(organization_id),
        Some(user_id),
        "finding.note_added",
        "finding",
        Some(finding_id),
        json!({}),
    )
    .await?;

    Ok(Json(CreateFindingNoteResponse { event }))
}

async fn list_finding_notes(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path((organization_id, finding_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Vec<FindingEvent>>, ApiError> {
    let user_id = current_user_id(&headers)?;
    require_membership(&pool, user_id, organization_id).await?;
    require_finding_in_org(&pool, organization_id, finding_id).await?;
    let rows = sqlx::query(
        r#"
        SELECT id, organization_id, finding_id, actor_user_id, event_type, note, created_at
        FROM finding_events
        WHERE organization_id = $1 AND finding_id = $2
        ORDER BY created_at DESC
        "#,
    )
    .bind(organization_id)
    .bind(finding_id)
    .fetch_all(&pool)
    .await
    .map_err(map_sql_error)?;

    Ok(Json(rows.iter().map(finding_event_from_row).collect()))
}

async fn create_slack_channel(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
    Json(request): Json<CreateSlackChannelRequest>,
) -> Result<Json<CreateSlackChannelResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;
    let role = require_membership(&pool, user_id, organization_id).await?;
    if !matches!(role, MemberRole::Owner | MemberRole::Admin) {
        return Err(ApiError::forbidden(
            "only organization owners and admins can configure Slack",
        ));
    }
    let name = validate_channel_name(&request.name)?;
    let webhook_url = validate_slack_webhook_url(&request.webhook_url)?;
    let row = sqlx::query(
        r#"
        INSERT INTO notification_channels (id, organization_id, kind, name, secret_ref, enabled)
        VALUES ($1, $2, 'slack', $3, $4, true)
        RETURNING id, organization_id, name, enabled, created_at
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(organization_id)
    .bind(name)
    .bind(webhook_url)
    .fetch_one(&pool)
    .await
    .map_err(map_sql_error)?;
    let channel = slack_channel_from_row(&row);

    record_audit(
        &pool,
        Some(organization_id),
        Some(user_id),
        "slack.channel_created",
        "notification_channel",
        Some(channel.id),
        json!({ "name": channel.name }),
    )
    .await?;

    Ok(Json(CreateSlackChannelResponse { channel }))
}

async fn queue_slack_alert(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path((organization_id, finding_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<QueueSlackAlertResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;
    require_membership(&pool, user_id, organization_id).await?;
    let finding = require_finding_in_org(&pool, organization_id, finding_id).await?;
    if let Some(alert) = active_alert_for_finding(&pool, finding_id).await? {
        let suppressed = insert_alert(
            &pool,
            organization_id,
            finding_id,
            alert.notification_channel_id,
            AlertStatus::Suppressed,
            alert.payload.clone(),
        )
        .await?;
        record_audit(
            &pool,
            Some(organization_id),
            Some(user_id),
            "alert.suppressed",
            "finding",
            Some(finding_id),
            json!({ "reason": "duplicate_active_alert" }),
        )
        .await?;
        return Ok(Json(QueueSlackAlertResponse { alert: suppressed }));
    }

    let channel = first_enabled_slack_channel(&pool, organization_id)
        .await?
        .ok_or_else(|| ApiError::conflict("no enabled Slack notification channel exists"))?;
    let domain = domain_for_asset(&pool, finding.asset_id)
        .await?
        .unwrap_or_else(|| "unknown-domain".to_string());
    let payload = build_slack_finding_alert(&finding, &domain).text;
    let alert = insert_alert(
        &pool,
        organization_id,
        finding_id,
        channel.id,
        AlertStatus::Queued,
        payload,
    )
    .await?;

    record_audit(
        &pool,
        Some(organization_id),
        Some(user_id),
        "alert.queued",
        "finding",
        Some(finding_id),
        json!({ "channel_id": channel.id }),
    )
    .await?;

    Ok(Json(QueueSlackAlertResponse { alert }))
}

async fn list_alerts(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<Vec<Alert>>, ApiError> {
    let user_id = current_user_id(&headers)?;
    require_membership(&pool, user_id, organization_id).await?;
    let rows = sqlx::query(
        r#"
        SELECT id, organization_id, finding_id, notification_channel_id, status::text AS status,
            payload, created_at, sent_at, attempts, next_attempt_at, error_message
        FROM alerts
        WHERE organization_id = $1
        ORDER BY created_at DESC
        "#,
    )
    .bind(organization_id)
    .fetch_all(&pool)
    .await
    .map_err(map_sql_error)?;

    Ok(Json(rows.iter().map(alert_from_row).collect()))
}

async fn deliver_alert(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path((organization_id, alert_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<QueueSlackAlertResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;
    require_membership(&pool, user_id, organization_id).await?;
    let row = sqlx::query(
        r#"
        SELECT alerts.id, alerts.organization_id, alerts.finding_id, alerts.notification_channel_id,
            alerts.status::text AS status, alerts.payload, alerts.created_at, alerts.sent_at,
            alerts.attempts, alerts.next_attempt_at, alerts.error_message,
            notification_channels.secret_ref
        FROM alerts
        INNER JOIN notification_channels ON notification_channels.id = alerts.notification_channel_id
        WHERE alerts.id = $1 AND alerts.organization_id = $2
        "#,
    )
    .bind(alert_id)
    .bind(organization_id)
    .fetch_optional(&pool)
    .await
    .map_err(map_sql_error)?
    .ok_or_else(|| ApiError::not_found("alert does not exist"))?;
    let alert = alert_from_row(&row);
    if alert.status != AlertStatus::Queued {
        return Err(ApiError::conflict("only queued alerts can be delivered"));
    }

    record_audit(
        &pool,
        Some(organization_id),
        Some(user_id),
        "alert.delivery_started",
        "alert",
        Some(alert_id),
        json!({}),
    )
    .await?;

    let webhook_url: String = row.get("secret_ref");
    let delivered = deliver_slack_message(
        &webhook_url,
        &ceem_alerts::SlackMessage {
            text: alert.payload.clone(),
        },
    )
    .await;
    let (status, sent_at, metadata) = match delivered {
        Ok(result) => (
            AlertStatus::Sent,
            Some(Utc::now()),
            json!({ "status_code": result.status_code }),
        ),
        Err(error) => (
            AlertStatus::Failed,
            None,
            json!({ "error": error.to_string() }),
        ),
    };
    let updated = update_alert_delivery(&pool, alert_id, status, sent_at).await?;
    record_audit(
        &pool,
        Some(organization_id),
        Some(user_id),
        if status == AlertStatus::Sent {
            "alert.sent"
        } else {
            "alert.failed"
        },
        "alert",
        Some(alert_id),
        metadata,
    )
    .await?;

    Ok(Json(QueueSlackAlertResponse { alert: updated }))
}

async fn create_remediation_task(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path((organization_id, finding_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<CreateRemediationTaskRequest>,
) -> Result<Json<CreateRemediationTaskResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;
    require_membership(&pool, user_id, organization_id).await?;
    let finding = require_finding_in_org(&pool, organization_id, finding_id).await?;
    let title = validate_task_title(
        request
            .title
            .unwrap_or_else(|| format!("Remediate: {}", finding.title)),
    )?;
    let assignee = validate_optional_text(request.assignee, "assignee", 120)?;
    let row = sqlx::query(
        r#"
        INSERT INTO remediation_tasks (id, organization_id, finding_id, title, status, assignee)
        VALUES ($1, $2, $3, $4, 'open', $5)
        RETURNING id, organization_id, finding_id, title, status, assignee, created_at, updated_at
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(organization_id)
    .bind(finding_id)
    .bind(title)
    .bind(assignee)
    .fetch_one(&pool)
    .await
    .map_err(map_sql_error)?;
    let task = remediation_task_from_row(&row);

    record_audit(
        &pool,
        Some(organization_id),
        Some(user_id),
        "remediation.created",
        "remediation_task",
        Some(task.id),
        json!({ "finding_id": finding_id }),
    )
    .await?;

    Ok(Json(CreateRemediationTaskResponse { task }))
}

async fn list_remediation_tasks(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<Vec<RemediationTask>>, ApiError> {
    let user_id = current_user_id(&headers)?;
    require_membership(&pool, user_id, organization_id).await?;
    let rows = sqlx::query(
        r#"
        SELECT id, organization_id, finding_id, title, status, assignee, created_at, updated_at
        FROM remediation_tasks
        WHERE organization_id = $1
        ORDER BY updated_at DESC
        "#,
    )
    .bind(organization_id)
    .fetch_all(&pool)
    .await
    .map_err(map_sql_error)?;

    Ok(Json(rows.iter().map(remediation_task_from_row).collect()))
}

async fn update_remediation_status(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path((organization_id, task_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<UpdateRemediationStatusRequest>,
) -> Result<Json<UpdateRemediationStatusResponse>, ApiError> {
    let user_id = current_user_id(&headers)?;
    require_membership(&pool, user_id, organization_id).await?;
    let row = sqlx::query(
        r#"
        UPDATE remediation_tasks
        SET status = $3, updated_at = now()
        WHERE id = $1 AND organization_id = $2
        RETURNING id, organization_id, finding_id, title, status, assignee, created_at, updated_at
        "#,
    )
    .bind(task_id)
    .bind(organization_id)
    .bind(remediation_status_slug(request.status))
    .fetch_optional(&pool)
    .await
    .map_err(map_sql_error)?
    .ok_or_else(|| ApiError::not_found("remediation task does not exist"))?;
    let task = remediation_task_from_row(&row);
    let finding_status = match request.status {
        RemediationStatus::Open => FindingStatus::Open,
        RemediationStatus::InProgress | RemediationStatus::Blocked => FindingStatus::InProgress,
        RemediationStatus::Remediated => FindingStatus::Remediated,
        RemediationStatus::AcceptedRisk => FindingStatus::AcceptedRisk,
        RemediationStatus::FalsePositive => FindingStatus::FalsePositive,
    };
    sqlx::query("UPDATE findings SET status = $2::finding_status WHERE id = $1")
        .bind(task.finding_id)
        .bind(finding_status_slug(finding_status))
        .execute(&pool)
        .await
        .map_err(map_sql_error)?;
    record_audit(
        &pool,
        Some(organization_id),
        Some(user_id),
        "remediation.status_changed",
        "remediation_task",
        Some(task_id),
        json!({ "status": remediation_status_slug(request.status), "finding_id": task.finding_id }),
    )
    .await?;

    Ok(Json(UpdateRemediationStatusResponse { task }))
}

async fn list_audit_logs(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<Vec<AuditLog>>, ApiError> {
    let user_id = current_user_id(&headers)?;
    require_membership(&pool, user_id, organization_id).await?;
    let rows = sqlx::query(
        r#"
        SELECT id, organization_id, actor_user_id, action, target_type, target_id, metadata, created_at
        FROM audit_logs
        WHERE organization_id = $1
        ORDER BY created_at DESC
        "#,
    )
    .bind(organization_id)
    .fetch_all(&pool)
    .await
    .map_err(map_sql_error)?;

    Ok(Json(rows.iter().map(audit_log_from_row).collect()))
}

async fn claim_scan_job_asset(
    pool: &PgPool,
    user_id: Uuid,
    organization_id: Uuid,
    scan_job_id: Uuid,
    scan_type: &str,
) -> Result<(Uuid, String), ApiError> {
    let role = require_membership(pool, user_id, organization_id).await?;
    if matches!(role, MemberRole::Viewer) {
        return Err(ApiError::forbidden("viewers cannot run scan jobs"));
    }

    let row = sqlx::query(
        r#"
        UPDATE scan_jobs
        SET status = 'running',
            started_at = COALESCE(started_at, now()),
            locked_at = now(),
            scan_type = $4
        FROM assets
        WHERE scan_jobs.id = $1
          AND scan_jobs.organization_id = $2
          AND scan_jobs.asset_id = assets.id
          AND scan_jobs.status = 'queued'
        RETURNING scan_jobs.asset_id, assets.value AS domain
        "#,
    )
    .bind(scan_job_id)
    .bind(organization_id)
    .bind(user_id)
    .bind(scan_type)
    .fetch_optional(pool)
    .await
    .map_err(map_sql_error)?
    .ok_or_else(|| ApiError::conflict("scan job is not queued or does not exist"))?;

    Ok((row.get("asset_id"), row.get("domain")))
}

async fn complete_scan_job_with_result(
    pool: &PgPool,
    scan_job_id: Uuid,
    scan_result: &ScanResult,
) -> Result<ScanJob, ApiError> {
    let mut transaction = pool.begin().await.map_err(map_sql_error)?;
    sqlx::query(
        r#"
        INSERT INTO scan_results (id, scan_job_id, asset_id, source, observed_at, evidence)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(scan_result.id)
    .bind(scan_result.scan_job_id)
    .bind(scan_result.asset_id)
    .bind(&scan_result.source)
    .bind(scan_result.observed_at)
    .bind(serde_json::to_value(&scan_result.evidence).map_err(|_| ApiError::internal())?)
    .execute(&mut *transaction)
    .await
    .map_err(map_sql_error)?;
    let row = sqlx::query(
        r#"
        UPDATE scan_jobs
        SET status = 'completed', completed_at = now(), locked_at = NULL
        WHERE id = $1
        RETURNING id, organization_id, asset_id, requested_by, status::text AS status, reason,
            created_at, started_at, completed_at
        "#,
    )
    .bind(scan_job_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(map_sql_error)?;
    transaction.commit().await.map_err(map_sql_error)?;
    let scan_job = scan_job_from_row(&row);
    record_audit(
        pool,
        Some(scan_job.organization_id),
        None,
        "scan.completed",
        "scan_job",
        Some(scan_job.id),
        json!({ "scan_result_id": scan_result.id, "source": scan_result.source }),
    )
    .await?;
    Ok(scan_job)
}

async fn mark_scan_job_failed(
    pool: &PgPool,
    scan_job_id: Uuid,
    error_message: String,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE scan_jobs SET status = 'failed', completed_at = now(), locked_at = NULL, error_message = $2 WHERE id = $1",
    )
    .bind(scan_job_id)
    .bind(error_message)
    .execute(pool)
    .await
    .map_err(map_sql_error)?;
    Ok(())
}

async fn upsert_findings(
    pool: &PgPool,
    scan_result: &ScanResult,
) -> Result<Vec<Finding>, ApiError> {
    let mut findings = Vec::new();
    for draft in derive_findings_from_scan_result(scan_result) {
        let risk_score = calculate_finding_risk_score(draft.severity, draft.confidence, 1, 0, true);
        let risk_factors = finding_risk_factors(draft.severity, draft.confidence, 1, 0, true);
        let row = sqlx::query(
            r#"
            INSERT INTO findings (
                id, organization_id, asset_id, rule_id, title, severity, confidence,
                status, evidence, remediation, occurrence_count, risk_score, risk_factors,
                first_seen_at, last_seen_at
            )
            VALUES ($1, $2, $3, $4, $5, $6::severity, $7::confidence, 'open',
                $8, $9, 1, $10, $11, now(), now())
            ON CONFLICT (asset_id, rule_id)
            DO UPDATE SET
                title = EXCLUDED.title,
                severity = EXCLUDED.severity,
                confidence = EXCLUDED.confidence,
                evidence = EXCLUDED.evidence,
                remediation = EXCLUDED.remediation,
                occurrence_count = findings.occurrence_count + 1,
                risk_score = LEAST(100, EXCLUDED.risk_score + LEAST(20, findings.occurrence_count * 4)),
                risk_factors = jsonb_set(
                    EXCLUDED.risk_factors,
                    '{occurrence_count}',
                    to_jsonb(findings.occurrence_count + 1)
                ),
                last_seen_at = now(),
                status = CASE
                    WHEN findings.status = 'remediated' THEN 'reopened'::finding_status
                    ELSE findings.status
                END
            RETURNING id, organization_id, asset_id, rule_id, title, severity::text AS severity,
                confidence::text AS confidence, status::text AS status, evidence, remediation,
                occurrence_count, risk_score, risk_factors, first_seen_at, last_seen_at
            "#,
        )
        .bind(Uuid::now_v7())
        .bind(scan_result.organization_id)
        .bind(scan_result.asset_id)
        .bind(&draft.rule_id)
        .bind(&draft.title)
        .bind(severity_slug(draft.severity))
        .bind(confidence_slug(draft.confidence))
        .bind(&draft.evidence)
        .bind(&draft.remediation)
        .bind(risk_score)
        .bind(risk_factors)
        .fetch_one(pool)
        .await
        .map_err(map_sql_error)?;
        findings.push(finding_from_row(&row));
    }
    Ok(findings)
}

async fn insert_finding_event(
    pool: &PgPool,
    organization_id: Uuid,
    finding_id: Uuid,
    actor_user_id: Uuid,
    event_type: &str,
    note: Option<String>,
) -> Result<FindingEvent, ApiError> {
    let row = sqlx::query(
        r#"
        INSERT INTO finding_events (id, organization_id, finding_id, actor_user_id, event_type, note)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id, organization_id, finding_id, actor_user_id, event_type, note, created_at
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(organization_id)
    .bind(finding_id)
    .bind(actor_user_id)
    .bind(event_type)
    .bind(note)
    .fetch_one(pool)
    .await
    .map_err(map_sql_error)?;

    Ok(finding_event_from_row(&row))
}

async fn insert_alert(
    pool: &PgPool,
    organization_id: Uuid,
    finding_id: Uuid,
    channel_id: Uuid,
    status: AlertStatus,
    payload: String,
) -> Result<Alert, ApiError> {
    let row = sqlx::query(
        r#"
        INSERT INTO alerts (id, organization_id, finding_id, notification_channel_id, status, payload)
        VALUES ($1, $2, $3, $4, $5::alert_status, $6)
        RETURNING id, organization_id, finding_id, notification_channel_id, status::text AS status,
            payload, created_at, sent_at, attempts, next_attempt_at, error_message
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(organization_id)
    .bind(finding_id)
    .bind(channel_id)
    .bind(alert_status_slug(status))
    .bind(json!({ "text": payload }))
    .fetch_one(pool)
    .await
    .map_err(map_sql_error)?;
    Ok(alert_from_row(&row))
}

async fn update_alert_delivery(
    pool: &PgPool,
    alert_id: Uuid,
    status: AlertStatus,
    sent_at: Option<chrono::DateTime<Utc>>,
) -> Result<Alert, ApiError> {
    let row = sqlx::query(
        r#"
        UPDATE alerts
        SET status = $2::alert_status, sent_at = $3, locked_at = NULL
        WHERE id = $1
        RETURNING id, organization_id, finding_id, notification_channel_id, status::text AS status,
            payload, created_at, sent_at, attempts, next_attempt_at, error_message
        "#,
    )
    .bind(alert_id)
    .bind(alert_status_slug(status))
    .bind(sent_at)
    .fetch_one(pool)
    .await
    .map_err(map_sql_error)?;
    Ok(alert_from_row(&row))
}

async fn record_audit(
    pool: &PgPool,
    organization_id: Option<Uuid>,
    actor_user_id: Option<Uuid>,
    action: &str,
    target_type: &str,
    target_id: Option<Uuid>,
    metadata: Value,
) -> Result<(), ApiError> {
    sqlx::query(
        r#"
        INSERT INTO audit_logs
            (id, organization_id, actor_user_id, action, target_type, target_id, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(organization_id)
    .bind(actor_user_id)
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(metadata)
    .execute(pool)
    .await
    .map_err(map_sql_error)?;
    Ok(())
}

async fn require_user(pool: &PgPool, user_id: Uuid) -> Result<UserAccount, ApiError> {
    let row = sqlx::query("SELECT id, email, display_name, created_at FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .map_err(map_sql_error)?
        .ok_or_else(|| ApiError::unauthorized("user does not exist"))?;
    Ok(user_from_row(&row))
}

async fn require_membership(
    pool: &PgPool,
    user_id: Uuid,
    organization_id: Uuid,
) -> Result<MemberRole, ApiError> {
    require_user(pool, user_id).await?;
    if organization_by_id(pool, organization_id).await?.is_none() {
        return Err(ApiError::not_found("organization does not exist"));
    }
    let row = sqlx::query(
        "SELECT role::text AS role FROM organization_members WHERE organization_id = $1 AND user_id = $2",
    )
    .bind(organization_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(map_sql_error)?
    .ok_or_else(|| ApiError::forbidden("user is not a member of this organization"))?;
    Ok(parse_member_role(row.get("role")))
}

async fn require_asset_in_org(
    pool: &PgPool,
    organization_id: Uuid,
    asset_id: Uuid,
) -> Result<DomainAsset, ApiError> {
    let row = sqlx::query(
        r#"
        SELECT id, organization_id, value, authorization_attested_by,
            authorization_attested_at, created_at
        FROM assets
        WHERE id = $1 AND organization_id = $2
        "#,
    )
    .bind(asset_id)
    .bind(organization_id)
    .fetch_optional(pool)
    .await
    .map_err(map_sql_error)?
    .ok_or_else(|| ApiError::not_found("domain asset does not exist"))?;
    Ok(domain_asset_from_row(&row))
}

async fn require_finding_in_org(
    pool: &PgPool,
    organization_id: Uuid,
    finding_id: Uuid,
) -> Result<Finding, ApiError> {
    let row = sqlx::query(
        r#"
        SELECT id, organization_id, asset_id, rule_id, title, severity::text AS severity,
            confidence::text AS confidence, status::text AS status, evidence, remediation,
            occurrence_count, risk_score, risk_factors, first_seen_at, last_seen_at
        FROM findings
        WHERE id = $1 AND organization_id = $2
        "#,
    )
    .bind(finding_id)
    .bind(organization_id)
    .fetch_optional(pool)
    .await
    .map_err(map_sql_error)?
    .ok_or_else(|| ApiError::not_found("finding does not exist"))?;
    Ok(finding_from_row(&row))
}

async fn scan_result_by_id(
    pool: &PgPool,
    organization_id: Uuid,
    scan_result_id: Uuid,
) -> Result<ScanResult, ApiError> {
    let row = sqlx::query(
        r#"
        SELECT scan_results.id, scan_results.scan_job_id, scan_results.asset_id,
            scan_jobs.organization_id, scan_results.source, scan_results.observed_at,
            scan_results.evidence
        FROM scan_results
        INNER JOIN scan_jobs ON scan_jobs.id = scan_results.scan_job_id
        WHERE scan_results.id = $1 AND scan_jobs.organization_id = $2
        "#,
    )
    .bind(scan_result_id)
    .bind(organization_id)
    .fetch_optional(pool)
    .await
    .map_err(map_sql_error)?
    .ok_or_else(|| ApiError::not_found("scan result does not exist"))?;
    scan_result_from_row(&row)
}

async fn find_user_by_email(
    pool: &PgPool,
    email: &str,
) -> Result<Option<(UserAccount, String)>, ApiError> {
    let row = sqlx::query(
        "SELECT id, email, display_name, password_hash, created_at FROM users WHERE email = $1",
    )
    .bind(email)
    .fetch_optional(pool)
    .await
    .map_err(map_sql_error)?;
    Ok(row.map(|row| (user_from_row(&row), row.get("password_hash"))))
}

async fn organization_by_id(
    pool: &PgPool,
    organization_id: Uuid,
) -> Result<Option<Organization>, ApiError> {
    let row = sqlx::query("SELECT id, name, slug, created_at FROM organizations WHERE id = $1")
        .bind(organization_id)
        .fetch_optional(pool)
        .await
        .map_err(map_sql_error)?;
    Ok(row.map(|row| organization_from_row(&row)))
}

async fn organization_by_slug(pool: &PgPool, slug: &str) -> Result<Option<Organization>, ApiError> {
    let row = sqlx::query("SELECT id, name, slug, created_at FROM organizations WHERE slug = $1")
        .bind(slug)
        .fetch_optional(pool)
        .await
        .map_err(map_sql_error)?;
    Ok(row.map(|row| organization_from_row(&row)))
}

async fn list_members(
    pool: &PgPool,
    organization_id: Uuid,
) -> Result<Vec<OrganizationMember>, ApiError> {
    let rows = sqlx::query(
        r#"
        SELECT users.id, users.email, users.display_name, users.created_at AS user_created_at,
            organization_members.role::text AS role,
            organization_members.created_at AS membership_created_at
        FROM organization_members
        INNER JOIN users ON users.id = organization_members.user_id
        WHERE organization_members.organization_id = $1
        ORDER BY users.email ASC
        "#,
    )
    .bind(organization_id)
    .fetch_all(pool)
    .await
    .map_err(map_sql_error)?;
    Ok(rows.iter().map(organization_member_from_row).collect())
}

async fn active_alert_for_finding(
    pool: &PgPool,
    finding_id: Uuid,
) -> Result<Option<Alert>, ApiError> {
    let row = sqlx::query(
        r#"
        SELECT id, organization_id, finding_id, notification_channel_id, status::text AS status,
            payload, created_at, sent_at
        FROM alerts
        WHERE finding_id = $1
          AND status IN ('queued', 'sent', 'suppressed')
          AND created_at >= now() - interval '24 hours'
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(finding_id)
    .fetch_optional(pool)
    .await
    .map_err(map_sql_error)?;
    Ok(row.map(|row| alert_from_row(&row)))
}

async fn first_enabled_slack_channel(
    pool: &PgPool,
    organization_id: Uuid,
) -> Result<Option<SlackNotificationChannel>, ApiError> {
    let row = sqlx::query(
        r#"
        SELECT id, organization_id, name, enabled, created_at
        FROM notification_channels
        WHERE organization_id = $1 AND kind = 'slack' AND enabled = true
        ORDER BY created_at ASC
        LIMIT 1
        "#,
    )
    .bind(organization_id)
    .fetch_optional(pool)
    .await
    .map_err(map_sql_error)?;
    Ok(row.map(|row| slack_channel_from_row(&row)))
}

async fn domain_for_asset(pool: &PgPool, asset_id: Uuid) -> Result<Option<String>, ApiError> {
    let row = sqlx::query("SELECT value FROM assets WHERE id = $1")
        .bind(asset_id)
        .fetch_optional(pool)
        .await
        .map_err(map_sql_error)?;
    Ok(row.map(|row| row.get("value")))
}

fn user_from_row(row: &PgRow) -> UserAccount {
    UserAccount {
        id: row.get("id"),
        email: row.get("email"),
        display_name: row.get("display_name"),
        created_at: row.get("created_at"),
    }
}

fn organization_from_row(row: &PgRow) -> Organization {
    Organization {
        id: row.get("id"),
        name: row.get("name"),
        slug: row.get("slug"),
        created_at: row.get("created_at"),
    }
}

fn membership_from_row(row: &PgRow) -> OrganizationMembership {
    OrganizationMembership {
        organization_id: row.get("organization_id"),
        user_id: row.get("user_id"),
        role: parse_member_role(row.get("role")),
        created_at: row.get("created_at"),
    }
}

fn organization_member_from_row(row: &PgRow) -> OrganizationMember {
    OrganizationMember {
        user: UserAccount {
            id: row.get("id"),
            email: row.get("email"),
            display_name: row.get("display_name"),
            created_at: row.get("user_created_at"),
        },
        role: parse_member_role(row.get("role")),
        created_at: row.get("membership_created_at"),
    }
}

fn invite_from_row(row: &PgRow) -> OrganizationInvite {
    OrganizationInvite {
        id: row.get("id"),
        organization_id: row.get("organization_id"),
        email: row.get("email"),
        role: parse_member_role(row.get("role")),
        token: row.get("token_hash"),
        invited_by: row.get("invited_by"),
        accepted_at: row.get("accepted_at"),
        created_at: row.get("created_at"),
    }
}

fn domain_asset_from_row(row: &PgRow) -> DomainAsset {
    DomainAsset {
        id: row.get("id"),
        organization_id: row.get("organization_id"),
        domain: row.get("value"),
        authorization_attested_by: row.get("authorization_attested_by"),
        authorization_attested_at: row.get("authorization_attested_at"),
        created_at: row.get("created_at"),
    }
}

fn scan_job_from_row(row: &PgRow) -> ScanJob {
    ScanJob {
        id: row.get("id"),
        organization_id: row.get("organization_id"),
        asset_id: row.get("asset_id"),
        requested_by: row.get("requested_by"),
        status: parse_scan_status(row.get("status")),
        reason: row.get("reason"),
        created_at: row.get("created_at"),
        started_at: row.get("started_at"),
        completed_at: row.get("completed_at"),
    }
}

fn scheduled_scan_from_row(row: &PgRow) -> ScheduledScan {
    ScheduledScan {
        id: row.get("id"),
        organization_id: row.get("organization_id"),
        asset_id: row.get("asset_id"),
        cadence: parse_scan_cadence(row.get("cadence")),
        profile: parse_scan_profile(row.get("profile")),
        enabled: row.get("enabled"),
        next_run_at: row.get("next_run_at"),
        last_enqueued_at: row.get("last_enqueued_at"),
        created_by: row.get("created_by"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

fn scan_result_from_row(row: &PgRow) -> Result<ScanResult, ApiError> {
    let evidence: Value = row.get("evidence");
    Ok(ScanResult {
        id: row.get("id"),
        organization_id: row.get("organization_id"),
        asset_id: row.get("asset_id"),
        scan_job_id: row.get("scan_job_id"),
        source: row.get("source"),
        observed_at: row.get("observed_at"),
        evidence: serde_json::from_value(evidence).map_err(|_| ApiError::internal())?,
    })
}

fn finding_from_row(row: &PgRow) -> Finding {
    Finding {
        id: row.get("id"),
        organization_id: row.get("organization_id"),
        asset_id: row.get("asset_id"),
        rule_id: row.get("rule_id"),
        title: row.get("title"),
        severity: parse_severity(row.get("severity")),
        status: parse_finding_status(row.get("status")),
        confidence: parse_confidence(row.get("confidence")),
        evidence: row.get("evidence"),
        remediation: row.get("remediation"),
        occurrence_count: row.get("occurrence_count"),
        risk_score: row.get("risk_score"),
        risk_factors: row.get("risk_factors"),
        first_seen_at: row.get("first_seen_at"),
        last_seen_at: row.get("last_seen_at"),
    }
}

fn finding_event_from_row(row: &PgRow) -> FindingEvent {
    FindingEvent {
        id: row.get("id"),
        organization_id: row.get("organization_id"),
        finding_id: row.get("finding_id"),
        actor_user_id: row.get("actor_user_id"),
        event_type: row.get("event_type"),
        note: row.get("note"),
        created_at: row.get("created_at"),
    }
}

fn slack_channel_from_row(row: &PgRow) -> SlackNotificationChannel {
    SlackNotificationChannel {
        id: row.get("id"),
        organization_id: row.get("organization_id"),
        name: row.get("name"),
        enabled: row.get("enabled"),
        created_at: row.get("created_at"),
    }
}

fn alert_from_row(row: &PgRow) -> Alert {
    let payload: Value = row.get("payload");
    let payload = payload
        .get("text")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| payload.to_string());
    Alert {
        id: row.get("id"),
        organization_id: row.get("organization_id"),
        finding_id: row.get("finding_id"),
        notification_channel_id: row.get("notification_channel_id"),
        status: parse_alert_status(row.get("status")),
        payload,
        created_at: row.get("created_at"),
        sent_at: row.get("sent_at"),
        attempts: row.get("attempts"),
        next_attempt_at: row.get("next_attempt_at"),
        error_message: row.get("error_message"),
    }
}

fn remediation_task_from_row(row: &PgRow) -> RemediationTask {
    RemediationTask {
        id: row.get("id"),
        organization_id: row.get("organization_id"),
        finding_id: row.get("finding_id"),
        title: row.get("title"),
        status: parse_remediation_status(row.get("status")),
        assignee: row.get("assignee"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

fn audit_log_from_row(row: &PgRow) -> AuditLog {
    AuditLog {
        id: row.get("id"),
        organization_id: row.get("organization_id"),
        actor_user_id: row.get("actor_user_id"),
        action: row.get("action"),
        target_type: row.get("target_type"),
        target_id: row.get("target_id"),
        metadata: row.get("metadata"),
        created_at: row.get("created_at"),
    }
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

fn validate_scan_reason(input: Option<String>) -> Result<Option<String>, ApiError> {
    validate_optional_text(input, "scan reason", 240)
}

fn enforce_auth_rate_limit(key: &str) -> Result<(), ApiError> {
    const WINDOW_SECONDS: i64 = 60;
    const MAX_ATTEMPTS: usize = 12;

    static ATTEMPTS: OnceLock<Mutex<HashMap<String, VecDeque<chrono::DateTime<Utc>>>>> =
        OnceLock::new();

    let now = Utc::now();
    let attempts = ATTEMPTS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut attempts = attempts.lock().map_err(|_| ApiError::internal())?;
    let entries = attempts.entry(key.to_string()).or_default();
    while let Some(oldest) = entries.front() {
        if now.signed_duration_since(*oldest).num_seconds() > WINDOW_SECONDS {
            entries.pop_front();
        } else {
            break;
        }
    }
    if entries.len() >= MAX_ATTEMPTS {
        return Err(ApiError::too_many_requests(
            "too many authentication attempts; wait before retrying",
        ));
    }
    entries.push_back(now);
    Ok(())
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
        .ok_or_else(|| ApiError::unauthorized("authorization header is required"))?;
    let value = value
        .to_str()
        .map_err(|_| ApiError::unauthorized("x-ceem-user-id must be a UUID"))?;
    Uuid::parse_str(value).map_err(|_| ApiError::unauthorized("x-ceem-user-id must be a UUID"))
}

fn member_role_slug(role: MemberRole) -> &'static str {
    match role {
        MemberRole::Owner => "owner",
        MemberRole::Admin => "admin",
        MemberRole::Member => "member",
        MemberRole::Viewer => "viewer",
    }
}

fn parse_member_role(value: &str) -> MemberRole {
    match value {
        "owner" => MemberRole::Owner,
        "admin" => MemberRole::Admin,
        "member" => MemberRole::Member,
        "viewer" => MemberRole::Viewer,
        _ => MemberRole::Viewer,
    }
}

fn parse_scan_status(value: &str) -> ScanStatus {
    match value {
        "queued" => ScanStatus::Queued,
        "running" => ScanStatus::Running,
        "completed" => ScanStatus::Completed,
        "failed" => ScanStatus::Failed,
        "canceled" => ScanStatus::Canceled,
        _ => ScanStatus::Failed,
    }
}

fn scan_cadence_slug(cadence: ScanCadence) -> &'static str {
    match cadence {
        ScanCadence::Manual => "manual",
        ScanCadence::Daily => "daily",
        ScanCadence::Weekly => "weekly",
    }
}

fn parse_scan_cadence(value: &str) -> ScanCadence {
    match value {
        "manual" => ScanCadence::Manual,
        "daily" => ScanCadence::Daily,
        "weekly" => ScanCadence::Weekly,
        _ => ScanCadence::Manual,
    }
}

fn scan_profile_slug(profile: ScanProfile) -> &'static str {
    match profile {
        ScanProfile::DnsBaseline => "dns_baseline",
        ScanProfile::HttpProbe => "http_probe",
        ScanProfile::DnsPolicy => "dns_policy",
        ScanProfile::FullDomainBaseline => "full_domain_baseline",
    }
}

fn parse_scan_profile(value: &str) -> ScanProfile {
    match value {
        "dns_baseline" => ScanProfile::DnsBaseline,
        "http_probe" => ScanProfile::HttpProbe,
        "dns_policy" => ScanProfile::DnsPolicy,
        "full_domain_baseline" => ScanProfile::FullDomainBaseline,
        _ => ScanProfile::DnsBaseline,
    }
}

fn next_run_for_cadence(cadence: ScanCadence) -> Option<chrono::DateTime<Utc>> {
    match cadence {
        ScanCadence::Manual => None,
        ScanCadence::Daily => Some(Utc::now() + Duration::days(1)),
        ScanCadence::Weekly => Some(Utc::now() + Duration::weeks(1)),
    }
}

fn severity_slug(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn parse_severity(value: &str) -> Severity {
    match value {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => Severity::Info,
    }
}

fn confidence_slug(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
    }
}

fn parse_confidence(value: &str) -> Confidence {
    match value {
        "low" => Confidence::Low,
        "medium" => Confidence::Medium,
        "high" => Confidence::High,
        _ => Confidence::Low,
    }
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

fn parse_finding_status(value: &str) -> FindingStatus {
    match value {
        "open" => FindingStatus::Open,
        "accepted_risk" => FindingStatus::AcceptedRisk,
        "false_positive" => FindingStatus::FalsePositive,
        "in_progress" => FindingStatus::InProgress,
        "remediated" => FindingStatus::Remediated,
        "reopened" => FindingStatus::Reopened,
        _ => FindingStatus::Open,
    }
}

fn alert_status_slug(status: AlertStatus) -> &'static str {
    match status {
        AlertStatus::Queued => "queued",
        AlertStatus::Sent => "sent",
        AlertStatus::Failed => "failed",
        AlertStatus::Suppressed => "suppressed",
    }
}

fn parse_alert_status(value: &str) -> AlertStatus {
    match value {
        "queued" => AlertStatus::Queued,
        "sent" => AlertStatus::Sent,
        "failed" => AlertStatus::Failed,
        "suppressed" => AlertStatus::Suppressed,
        _ => AlertStatus::Failed,
    }
}

fn remediation_status_slug(status: RemediationStatus) -> &'static str {
    match status {
        RemediationStatus::Open => "open",
        RemediationStatus::InProgress => "in_progress",
        RemediationStatus::Blocked => "blocked",
        RemediationStatus::Remediated => "remediated",
        RemediationStatus::AcceptedRisk => "accepted_risk",
        RemediationStatus::FalsePositive => "false_positive",
    }
}

fn parse_remediation_status(value: &str) -> RemediationStatus {
    match value {
        "open" => RemediationStatus::Open,
        "in_progress" => RemediationStatus::InProgress,
        "blocked" => RemediationStatus::Blocked,
        "remediated" => RemediationStatus::Remediated,
        "accepted_risk" => RemediationStatus::AcceptedRisk,
        "false_positive" => RemediationStatus::FalsePositive,
        _ => RemediationStatus::Open,
    }
}

fn map_sql_error(error: sqlx::Error) -> ApiError {
    if let sqlx::Error::Database(database_error) = &error
        && database_error.is_unique_violation()
    {
        return ApiError::conflict("resource already exists");
    }
    ApiError::internal()
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

    fn too_many_requests(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
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
    fn allows_auth_rate_limit_under_threshold() {
        let key = format!("rate-{}", Uuid::now_v7());
        assert!(enforce_auth_rate_limit(&key).is_ok());
    }

    #[test]
    fn maps_database_status_slugs() {
        assert_eq!(parse_scan_status("queued"), ScanStatus::Queued);
        assert_eq!(
            finding_status_slug(FindingStatus::AcceptedRisk),
            "accepted_risk"
        );
        assert_eq!(
            parse_remediation_status("blocked"),
            RemediationStatus::Blocked
        );
    }
}
