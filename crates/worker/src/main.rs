use std::time::Duration;

use ceem_db::{DatabaseConfig, PostgresRepository};
use ceem_findings::derive_findings_from_scan_result;
use ceem_scanner::{collect_dns_policy_baseline, probe_http_endpoint, resolve_dns_baseline};
use ceem_shared::{ScanEvidence, ScanResult, ScanStatus};
use chrono::Utc;
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
    let Some(job) = claim_next_scan_job(pool).await? else {
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
                first_seen_at,
                last_seen_at
            )
            VALUES ($1, $2, $3, $4, $5, $6::severity, $7::confidence, 'open', $8, $9, now(), now())
            ON CONFLICT (asset_id, rule_id)
            DO UPDATE SET
                evidence = EXCLUDED.evidence,
                remediation = EXCLUDED.remediation,
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

fn scan_status_as_str(status: ScanStatus) -> &'static str {
    match status {
        ScanStatus::Queued => "queued",
        ScanStatus::Running => "running",
        ScanStatus::Completed => "completed",
        ScanStatus::Failed => "failed",
        ScanStatus::Canceled => "canceled",
    }
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
