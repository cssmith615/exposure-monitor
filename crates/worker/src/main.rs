use std::time::Duration;

use ceem_alerts::{SlackMessage, deliver_slack_message};
use ceem_db::{DatabaseConfig, PostgresRepository};
use ceem_findings::derive_findings_from_scan_result;
use ceem_scanner::{collect_dns_policy_baseline, probe_http_endpoint, resolve_dns_baseline};
use ceem_shared::{
    AlertStatus, ScanCadence, ScanEvidence, ScanProfile, ScanResult, ScanStatus,
    calculate_finding_risk_score, finding_risk_factors,
};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::{PgPool, Row};
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, fmt};
use uuid::Uuid;

#[derive(Debug, Clone)]
struct WorkerConfig {
    poll_interval: Duration,
    run_once: bool,
}

#[derive(Debug, Clone)]
struct ClaimedScanJob {
    id: Uuid,
    organization_id: Uuid,
    asset_id: Uuid,
    domain: String,
    scan_type: String,
}

#[derive(Debug, Clone)]
struct DueScheduledScan {
    id: Uuid,
    organization_id: Uuid,
    asset_id: Uuid,
    created_by: Uuid,
    cadence: ScanCadence,
    profile: ScanProfile,
}

#[derive(Debug, Clone)]
struct ClaimedAlert {
    id: Uuid,
    organization_id: Uuid,
    finding_id: Uuid,
    webhook_url: String,
    payload: String,
    attempts: i32,
    max_attempts: i32,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).json().init();

    let config = WorkerConfig {
        poll_interval: Duration::from_secs(
            std::env::var("CEEM_WORKER_POLL_SECONDS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(15),
        ),
        run_once: std::env::var("CEEM_WORKER_RUN_ONCE")
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false),
    };
    let repository = PostgresRepository::connect(&DatabaseConfig::from_env()?).await?;
    repository.migrate().await?;

    info!(run_once = config.run_once, "CEEM worker started");

    loop {
        match run_worker_tick(repository.pool()).await {
            Ok(true) => {}
            Ok(false) if config.run_once => break,
            Ok(false) => tokio::time::sleep(config.poll_interval).await,
            Err(error) if config.run_once => return Err(error),
            Err(error) => {
                error!(%error, "worker tick failed");
                tokio::time::sleep(config.poll_interval).await;
            }
        }
    }

    Ok(())
}

async fn run_worker_tick(pool: &PgPool) -> anyhow::Result<bool> {
    if enqueue_due_scheduled_scans(pool).await? {
        return Ok(true);
    }

    let Some(job) = claim_next_scan_job(pool).await? else {
        if let Some(alert) = claim_next_alert(pool).await? {
            deliver_claimed_alert(pool, alert).await?;
            return Ok(true);
        }

        return Ok(false);
    };

    info!(
        scan_job_id = %job.id,
        domain = %job.domain,
        scan_type = %job.scan_type,
        "claimed scan job"
    );

    match execute_scan_job(&job).await {
        Ok(scan_result) => {
            persist_scan_result(pool, &scan_result).await?;
            persist_findings(pool, &scan_result).await?;
            complete_scan_job(pool, job.id, ScanStatus::Completed, None).await?;
            info!(scan_job_id = %job.id, "completed scan job");
        }
        Err(error) => {
            warn!(scan_job_id = %job.id, %error, "scan job failed");
            complete_scan_job(pool, job.id, ScanStatus::Failed, Some(error.to_string())).await?;
        }
    }

    Ok(true)
}

async fn enqueue_due_scheduled_scans(pool: &PgPool) -> Result<bool, sqlx::Error> {
    let mut transaction = pool.begin().await?;
    let rows = sqlx::query(
        r#"
        SELECT id, organization_id, asset_id, cadence::text AS cadence, profile::text AS profile,
            created_by
        FROM scheduled_scans
        WHERE enabled = true
          AND next_run_at IS NOT NULL
          AND next_run_at <= now()
        ORDER BY next_run_at ASC
        FOR UPDATE SKIP LOCKED
        LIMIT 10
        "#,
    )
    .fetch_all(&mut *transaction)
    .await?;

    let due_scans = rows
        .iter()
        .map(|row| DueScheduledScan {
            id: row.get("id"),
            organization_id: row.get("organization_id"),
            asset_id: row.get("asset_id"),
            created_by: row.get("created_by"),
            cadence: parse_scan_cadence(row.get("cadence")),
            profile: parse_scan_profile(row.get("profile")),
        })
        .collect::<Vec<_>>();

    for scheduled_scan in &due_scans {
        for scan_type in scan_types_for_profile(scheduled_scan.profile) {
            sqlx::query(
                r#"
                INSERT INTO scan_jobs (
                    id, organization_id, requested_by, asset_id, reason, scan_type, next_run_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, now())
                "#,
            )
            .bind(Uuid::now_v7())
            .bind(scheduled_scan.organization_id)
            .bind(scheduled_scan.created_by)
            .bind(scheduled_scan.asset_id)
            .bind(format!(
                "Scheduled {} scan",
                scan_profile_as_str(scheduled_scan.profile)
            ))
            .bind(scan_type)
            .execute(&mut *transaction)
            .await?;
        }

        sqlx::query(
            r#"
            UPDATE scheduled_scans
            SET last_enqueued_at = now(),
                next_run_at = $2,
                updated_at = now()
            WHERE id = $1
            "#,
        )
        .bind(scheduled_scan.id)
        .bind(next_run_for_cadence(scheduled_scan.cadence))
        .execute(&mut *transaction)
        .await?;

        insert_audit_in_transaction(
            &mut transaction,
            scheduled_scan.organization_id,
            "scheduled_scan.enqueued",
            "scheduled_scan",
            scheduled_scan.id,
            json!({ "profile": scan_profile_as_str(scheduled_scan.profile) }),
        )
        .await?;
    }

    transaction.commit().await?;
    Ok(!due_scans.is_empty())
}

async fn claim_next_scan_job(pool: &PgPool) -> Result<Option<ClaimedScanJob>, sqlx::Error> {
    let row = sqlx::query(
        r#"
        WITH claimed AS (
            SELECT scan_jobs.id
            FROM scan_jobs
            INNER JOIN assets ON assets.id = scan_jobs.asset_id
            WHERE scan_jobs.status = 'queued'
              AND scan_jobs.asset_id IS NOT NULL
              AND (scan_jobs.next_run_at IS NULL OR scan_jobs.next_run_at <= now())
            ORDER BY scan_jobs.created_at ASC
            FOR UPDATE SKIP LOCKED
            LIMIT 1
        )
        UPDATE scan_jobs
        SET status = 'running',
            attempts = attempts + 1,
            started_at = COALESCE(started_at, now()),
            locked_at = now()
        FROM claimed, assets
        WHERE scan_jobs.id = claimed.id
          AND assets.id = scan_jobs.asset_id
        RETURNING
            scan_jobs.id,
            scan_jobs.organization_id,
            scan_jobs.asset_id,
            assets.value AS domain,
            scan_jobs.scan_type
        "#,
    )
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|row| ClaimedScanJob {
        id: row.get("id"),
        organization_id: row.get("organization_id"),
        asset_id: row.get("asset_id"),
        domain: row.get("domain"),
        scan_type: row.get("scan_type"),
    }))
}

async fn execute_scan_job(job: &ClaimedScanJob) -> anyhow::Result<ScanResult> {
    let evidence = match job.scan_type.as_str() {
        "dns_baseline" => ScanEvidence::DnsBaseline(resolve_dns_baseline(&job.domain).await?),
        "http_probe" => ScanEvidence::HttpProbe(probe_http_endpoint(&job.domain, "https").await?),
        "dns_policy" => ScanEvidence::DnsPolicy(collect_dns_policy_baseline(&job.domain).await?),
        unknown => anyhow::bail!("unsupported scan type: {unknown}"),
    };

    Ok(ScanResult {
        id: Uuid::now_v7(),
        organization_id: job.organization_id,
        asset_id: job.asset_id,
        scan_job_id: job.id,
        source: job.scan_type.clone(),
        observed_at: Utc::now(),
        evidence,
    })
}

async fn persist_scan_result(pool: &PgPool, scan_result: &ScanResult) -> Result<(), sqlx::Error> {
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
    .bind(serde_json::to_value(&scan_result.evidence).unwrap_or(serde_json::Value::Null))
    .execute(pool)
    .await?;

    Ok(())
}

async fn persist_findings(pool: &PgPool, scan_result: &ScanResult) -> Result<(), sqlx::Error> {
    for draft in derive_findings_from_scan_result(scan_result) {
        let risk_score = calculate_finding_risk_score(draft.severity, draft.confidence, 1, 0, true);
        let risk_factors = finding_risk_factors(draft.severity, draft.confidence, 1, 0, true);
        sqlx::query(
            r#"
            INSERT INTO findings (
                id,
                organization_id,
                asset_id,
                rule_id,
                title,
                severity,
                confidence,
                status,
                evidence,
                remediation,
                occurrence_count,
                risk_score,
                risk_factors,
                first_seen_at,
                last_seen_at
            )
            VALUES (
                $1, $2, $3, $4, $5, $6::severity, $7::confidence, 'open', $8, $9,
                1, $10, $11, now(), now()
            )
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
            "#,
        )
        .bind(Uuid::now_v7())
        .bind(scan_result.organization_id)
        .bind(scan_result.asset_id)
        .bind(&draft.rule_id)
        .bind(&draft.title)
        .bind(severity_as_str(draft.severity))
        .bind(confidence_as_str(draft.confidence))
        .bind(&draft.evidence)
        .bind(&draft.remediation)
        .bind(risk_score)
        .bind(risk_factors)
        .execute(pool)
        .await?;
    }

    Ok(())
}

async fn complete_scan_job(
    pool: &PgPool,
    scan_job_id: Uuid,
    status: ScanStatus,
    error_message: Option<String>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE scan_jobs
        SET status = $2::scan_status,
            completed_at = now(),
            locked_at = NULL,
            error_message = $3
        WHERE id = $1
        "#,
    )
    .bind(scan_job_id)
    .bind(scan_status_as_str(status))
    .bind(error_message)
    .execute(pool)
    .await?;

    Ok(())
}

async fn claim_next_alert(pool: &PgPool) -> Result<Option<ClaimedAlert>, sqlx::Error> {
    let row = sqlx::query(
        r#"
        WITH claimed AS (
            SELECT alerts.id
            FROM alerts
            INNER JOIN notification_channels ON notification_channels.id = alerts.notification_channel_id
            WHERE alerts.status IN ('queued', 'failed')
              AND alerts.attempts < alerts.max_attempts
              AND (alerts.next_attempt_at IS NULL OR alerts.next_attempt_at <= now())
              AND notification_channels.kind = 'slack'
              AND notification_channels.enabled = true
            ORDER BY alerts.created_at ASC
            FOR UPDATE SKIP LOCKED
            LIMIT 1
        )
        UPDATE alerts
        SET status = 'queued',
            attempts = alerts.attempts + 1,
            locked_at = now()
        FROM claimed, notification_channels
        WHERE alerts.id = claimed.id
          AND notification_channels.id = alerts.notification_channel_id
        RETURNING
            alerts.id,
            alerts.organization_id,
            alerts.finding_id,
            alerts.payload,
            alerts.attempts,
            alerts.max_attempts,
            notification_channels.secret_ref AS webhook_url
        "#,
    )
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|row| {
        let payload: Value = row.get("payload");
        let payload = payload
            .get("text")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| payload.to_string());

        ClaimedAlert {
            id: row.get("id"),
            organization_id: row.get("organization_id"),
            finding_id: row.get("finding_id"),
            webhook_url: row.get("webhook_url"),
            payload,
            attempts: row.get("attempts"),
            max_attempts: row.get("max_attempts"),
        }
    }))
}

async fn deliver_claimed_alert(pool: &PgPool, alert: ClaimedAlert) -> anyhow::Result<()> {
    info!(
        alert_id = %alert.id,
        finding_id = %alert.finding_id,
        attempts = alert.attempts,
        "claimed Slack alert"
    );

    let delivered = deliver_slack_message(
        &alert.webhook_url,
        &SlackMessage {
            text: alert.payload.clone(),
        },
    )
    .await;

    match delivered {
        Ok(result) => {
            update_alert_delivery(
                pool,
                alert.id,
                AlertStatus::Sent,
                Some(Utc::now()),
                None,
                None,
            )
            .await?;
            insert_audit(
                pool,
                alert.organization_id,
                "alert.sent",
                "alert",
                alert.id,
                json!({ "status_code": result.status_code, "worker_delivery": true }),
            )
            .await?;
        }
        Err(error) => {
            let retry_at = if alert.attempts >= alert.max_attempts {
                None
            } else {
                Some(Utc::now() + retry_backoff(alert.attempts))
            };
            update_alert_delivery(
                pool,
                alert.id,
                AlertStatus::Failed,
                None,
                retry_at,
                Some(error.to_string()),
            )
            .await?;
            insert_audit(
                pool,
                alert.organization_id,
                "alert.failed",
                "alert",
                alert.id,
                json!({
                    "error": error.to_string(),
                    "attempts": alert.attempts,
                    "max_attempts": alert.max_attempts,
                    "worker_delivery": true
                }),
            )
            .await?;
        }
    }

    Ok(())
}

async fn update_alert_delivery(
    pool: &PgPool,
    alert_id: Uuid,
    status: AlertStatus,
    sent_at: Option<DateTime<Utc>>,
    next_attempt_at: Option<DateTime<Utc>>,
    error_message: Option<String>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE alerts
        SET status = $2::alert_status,
            sent_at = $3,
            next_attempt_at = $4,
            error_message = $5,
            locked_at = NULL
        WHERE id = $1
        "#,
    )
    .bind(alert_id)
    .bind(alert_status_as_str(status))
    .bind(sent_at)
    .bind(next_attempt_at)
    .bind(error_message)
    .execute(pool)
    .await?;

    Ok(())
}

async fn insert_audit(
    pool: &PgPool,
    organization_id: Uuid,
    action: &str,
    target_type: &str,
    target_id: Uuid,
    metadata: Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO audit_logs
            (id, organization_id, actor_user_id, action, target_type, target_id, metadata)
        VALUES ($1, $2, NULL, $3, $4, $5, $6)
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(organization_id)
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(metadata)
    .execute(pool)
    .await?;

    Ok(())
}

async fn insert_audit_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: Uuid,
    action: &str,
    target_type: &str,
    target_id: Uuid,
    metadata: Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO audit_logs
            (id, organization_id, actor_user_id, action, target_type, target_id, metadata)
        VALUES ($1, $2, NULL, $3, $4, $5, $6)
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(organization_id)
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(metadata)
    .execute(&mut **transaction)
    .await?;

    Ok(())
}

fn scan_status_as_str(status: ScanStatus) -> &'static str {
    match status {
        ScanStatus::Queued => "queued",
        ScanStatus::Running => "running",
        ScanStatus::Completed => "completed",
        ScanStatus::Failed => "failed",
        ScanStatus::Canceled => "canceled",
    }
}

fn alert_status_as_str(status: AlertStatus) -> &'static str {
    match status {
        AlertStatus::Queued => "queued",
        AlertStatus::Sent => "sent",
        AlertStatus::Failed => "failed",
        AlertStatus::Suppressed => "suppressed",
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

fn parse_scan_profile(value: &str) -> ScanProfile {
    match value {
        "dns_baseline" => ScanProfile::DnsBaseline,
        "http_probe" => ScanProfile::HttpProbe,
        "dns_policy" => ScanProfile::DnsPolicy,
        "full_domain_baseline" => ScanProfile::FullDomainBaseline,
        _ => ScanProfile::DnsBaseline,
    }
}

fn scan_profile_as_str(profile: ScanProfile) -> &'static str {
    match profile {
        ScanProfile::DnsBaseline => "dns_baseline",
        ScanProfile::HttpProbe => "http_probe",
        ScanProfile::DnsPolicy => "dns_policy",
        ScanProfile::FullDomainBaseline => "full_domain_baseline",
    }
}

fn scan_types_for_profile(profile: ScanProfile) -> Vec<&'static str> {
    match profile {
        ScanProfile::DnsBaseline => vec!["dns_baseline"],
        ScanProfile::HttpProbe => vec!["http_probe"],
        ScanProfile::DnsPolicy => vec!["dns_policy"],
        ScanProfile::FullDomainBaseline => vec!["dns_baseline", "http_probe", "dns_policy"],
    }
}

fn next_run_for_cadence(cadence: ScanCadence) -> Option<DateTime<Utc>> {
    match cadence {
        ScanCadence::Manual => None,
        ScanCadence::Daily => Some(Utc::now() + chrono::Duration::days(1)),
        ScanCadence::Weekly => Some(Utc::now() + chrono::Duration::weeks(1)),
    }
}

fn retry_backoff(attempts: i32) -> chrono::Duration {
    let exponent = attempts.saturating_sub(1).min(5) as u32;
    let seconds = 30_i64.saturating_mul(2_i64.pow(exponent)).min(900);
    chrono::Duration::seconds(seconds)
}

fn severity_as_str(severity: ceem_shared::Severity) -> &'static str {
    match severity {
        ceem_shared::Severity::Info => "info",
        ceem_shared::Severity::Low => "low",
        ceem_shared::Severity::Medium => "medium",
        ceem_shared::Severity::High => "high",
        ceem_shared::Severity::Critical => "critical",
    }
}

fn confidence_as_str(confidence: ceem_shared::Confidence) -> &'static str {
    match confidence {
        ceem_shared::Confidence::Low => "low",
        ceem_shared::Confidence::Medium => "medium",
        ceem_shared::Confidence::High => "high",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ceem_shared::{Confidence, Severity};

    #[test]
    fn maps_scan_status_values() {
        assert_eq!(scan_status_as_str(ScanStatus::Queued), "queued");
        assert_eq!(scan_status_as_str(ScanStatus::Failed), "failed");
    }

    #[test]
    fn maps_finding_enum_values() {
        assert_eq!(severity_as_str(Severity::High), "high");
        assert_eq!(confidence_as_str(Confidence::Medium), "medium");
    }
}
