use anyhow::Result;
use sqlx::SqlitePool;
use sqlx::sqlite::SqlitePoolOptions;
use chrono::Utc;
use crate::models::{CheckResult, CheckKind, CheckStatus, Subdomain};

pub async fn connect(path: &str) -> Result<SqlitePool> {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&format!("sqlite://{}?mode=rwc", path))
        .await?;

    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&pool)
        .await?;

    Ok(pool)
}

pub async fn migrate(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS clients (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL UNIQUE,
            created_at  TEXT NOT NULL
        )"
    ).execute(pool).await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS domains (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id   INTEGER NOT NULL REFERENCES clients(id),
            fqdn        TEXT NOT NULL,
            active      INTEGER NOT NULL DEFAULT 1,
            created_at  TEXT NOT NULL,
            UNIQUE(client_id, fqdn)
        )"
    ).execute(pool).await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS check_results (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_id   INTEGER NOT NULL REFERENCES domains(id),
            kind        TEXT NOT NULL,
            status      TEXT NOT NULL,
            detail      TEXT NOT NULL,
            expires_at  TEXT,
            checked_at  TEXT NOT NULL
        )"
    ).execute(pool).await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS subdomains (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_id   INTEGER NOT NULL REFERENCES domains(id),
            fqdn        TEXT NOT NULL,
            source      TEXT NOT NULL,
            first_seen  TEXT NOT NULL,
            last_seen   TEXT NOT NULL,
            active      INTEGER NOT NULL DEFAULT 1,
            UNIQUE(domain_id, fqdn)
        )"
    ).execute(pool).await?;

    Ok(())
}

pub async fn insert_client(pool: &SqlitePool, name: &str) -> Result<i64> {
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT OR IGNORE INTO clients (name, created_at) VALUES (?1, ?2)"
    )
    .bind(name)
    .bind(&now)
    .execute(pool)
    .await?;

    let row = sqlx::query_as::<_, (i64,)>(
        "SELECT id FROM clients WHERE name = ?1"
    )
    .bind(name)
    .fetch_one(pool)
    .await?;

    Ok(row.0)
}

pub async fn insert_domain(pool: &SqlitePool, client_id: i64, fqdn: &str) -> Result<i64> {
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT OR IGNORE INTO domains (client_id, fqdn, active, created_at) VALUES (?1, ?2, 1, ?3)"
    )
    .bind(client_id)
    .bind(fqdn)
    .bind(&now)
    .execute(pool)
    .await?;

    let row = sqlx::query_as::<_, (i64,)>(
        "SELECT id FROM domains WHERE client_id = ?1 AND fqdn = ?2"
    )
    .bind(client_id)
    .bind(fqdn)
    .fetch_one(pool)
    .await?;

    Ok(row.0)
}

pub async fn get_active_domains(pool: &SqlitePool) -> Result<Vec<(i64, String)>> {
    let rows = sqlx::query_as::<_, (i64, String)>(
        "SELECT id, fqdn FROM domains WHERE active = 1"
    )
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

pub async fn save_result(pool: &SqlitePool, result: &CheckResult) -> Result<i64> {
    let row = sqlx::query(
        "INSERT INTO check_results (domain_id, kind, status, detail, expires_at, checked_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
    )
    .bind(result.domain_id)
    .bind(result.kind.to_string())
    .bind(result.status.to_string())
    .bind(&result.detail)
    .bind(result.expires_at.map(|d| d.to_rfc3339()))
    .bind(result.checked_at.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(row.last_insert_rowid())
}

pub async fn get_latest_results(pool: &SqlitePool) -> Result<Vec<CheckResult>> {
    let rows = sqlx::query_as::<_, (i64, i64, String, String, String, Option<String>, String)>(
        "SELECT id, domain_id, kind, status, detail, expires_at, checked_at
        FROM check_results
        WHERE id IN (
            SELECT MAX(id) FROM check_results
            GROUP BY domain_id, kind
        )
        ORDER BY domain_id, kind"
    )
    .fetch_all(pool)
    .await?;

    let results = rows.into_iter().map(|(id, domain_id, kind, status, detail, expires_at, checked_at)| {
        CheckResult {
            id,
            domain_id,
            kind: match kind.as_str() {
                "TLS"           => CheckKind::Tls,
                "DOMAIN_EXPIRY" => CheckKind::DomainExpiry,
                "DNS_SPF"       => CheckKind::DnsSpf,
                "DNS_DMARC"     => CheckKind::DnsDmarc,
                "DNS_MX"        => CheckKind::DnsMx,
                "HTTP_HSTS"     => CheckKind::HttpHsts,
                "HTTP_REDIRECT" => CheckKind::HttpRedirect,
                _               => CheckKind::Tls,
            },
            status: match status.as_str() {
                "OK"       => CheckStatus::Ok,
                "WARNING"  => CheckStatus::Warning,
                "CRITICAL" => CheckStatus::Critical,
                _          => CheckStatus::Error,
            },
            detail,
            expires_at: expires_at.and_then(|s| s.parse().ok()),
            checked_at: checked_at.parse().unwrap_or_else(|_| Utc::now()),
        }
    }).collect();

    Ok(results)
}

pub async fn upsert_subdomain(
    pool: &SqlitePool,
    domain_id: i64,
    fqdn: &str,
    source: &str,
) -> Result<i64> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO subdomains (domain_id, fqdn, source, first_seen, last_seen)
         VALUES (?1, ?2, ?3, ?4, ?4)
         ON CONFLICT(domain_id, fqdn) DO UPDATE SET
             last_seen = excluded.last_seen,
             active = 1"
    )
    .bind(domain_id)
    .bind(fqdn)
    .bind(source)
    .bind(&now)
    .execute(pool)
    .await?;

    let row = sqlx::query_as::<_, (i64,)>(
        "SELECT id FROM subdomains WHERE domain_id = ?1 AND fqdn = ?2"
    )
    .bind(domain_id)
    .bind(fqdn)
    .fetch_one(pool)
    .await?;

    Ok(row.0)
}

pub async fn get_subdomains(
    pool: &SqlitePool,
    domain_id: i64,
) -> Result<Vec<Subdomain>> {
    let rows = sqlx::query_as::<_, (i64, i64, String, String, String, String, bool)>(
        "SELECT id, domain_id, fqdn, source, first_seen, last_seen, active
         FROM subdomains
         WHERE domain_id = ?1 AND active = 1
         ORDER BY fqdn"
    )
    .bind(domain_id)
    .fetch_all(pool)
    .await?;

    let subdomains = rows.into_iter().map(|(id, domain_id, fqdn, source, first_seen, last_seen, active)| {
        Subdomain {
            id,
            domain_id,
            fqdn,
            source,
            first_seen: first_seen.parse().unwrap_or_else(|_| Utc::now()),
            last_seen: last_seen.parse().unwrap_or_else(|_| Utc::now()),
            active,
        }
    }).collect();

    Ok(subdomains)
}

pub async fn get_all_subdomains_as_domains(
    pool: &SqlitePool,
) -> Result<Vec<(i64, String)>> {
    let rows = sqlx::query_as::<_, (i64, String)>(
        "SELECT id, fqdn FROM subdomains WHERE active = 1"
    )
    .fetch_all(pool)
    .await?;

    Ok(rows)
}