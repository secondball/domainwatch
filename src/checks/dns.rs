use anyhow::Result;
use chrono::Utc;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::*;

use crate::models::{CheckResult, CheckKind, CheckStatus};

async fn get_resolver() -> Result<TokioAsyncResolver> {
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::cloudflare(),
        ResolverOpts::default()
    );
    Ok(resolver)
}

pub async fn check_spf(domain_id: i64, fqdn: &str) -> Result<CheckResult> {
    let resolver = get_resolver().await?;
    let lookup = resolver.txt_lookup(fqdn).await;

    let (status, detail) = match lookup {
        Err(_) => (CheckStatus::Error, "TXT lookup failed".to_string()),
        Ok(records) => {
            let has_spf = records.iter().any(|r| {
                r.to_string().starts_with("v=spf1")
            });
            if has_spf {
                (CheckStatus::Ok, "SPF record present".to_string())
            } else {
                (CheckStatus::Critical, "No SPF record found".to_string())
            }
        }
    };

    Ok(CheckResult {
        id: 0,
        domain_id,
        kind: CheckKind::DnsSpf,
        status,
        detail,
        expires_at: None,
        checked_at: Utc::now(),
    })
}

pub async fn check_dmarc(domain_id: i64, fqdn: &str) -> Result<CheckResult> {
    let resolver = get_resolver().await?;
    let dmarc_host = format!("_dmarc.{}", fqdn);
    let lookup = resolver.txt_lookup(&dmarc_host).await;

    let (status, detail) = match lookup {
        Err(_) => (CheckStatus::Critical, "No DMARC record found".to_string()),
        Ok(records) => {
            let has_dmarc = records.iter().any(|r| {
                r.to_string().starts_with("v=DMARC1")
            });
            if has_dmarc {
                (CheckStatus::Ok, "DMARC record present".to_string())
            } else {
                (CheckStatus::Critical, "No DMARC record found".to_string())
            }
        }
    };

    Ok(CheckResult {
        id: 0,
        domain_id,
        kind: CheckKind::DnsDmarc,
        status,
        detail,
        expires_at: None,
        checked_at: Utc::now(),
    })
}

pub async fn check_mx(domain_id: i64, fqdn: &str) -> Result<CheckResult> {
    let resolver = get_resolver().await?;
    let lookup = resolver.mx_lookup(fqdn).await;

    let (status, detail) = match lookup {
        Err(_) => (CheckStatus::Warning, "No MX records found".to_string()),
        Ok(records) => {
            let count = records.iter().count();
            (CheckStatus::Ok, format!("{} MX record(s) found", count))
        }
    };

    Ok(CheckResult {
        id: 0,
        domain_id,
        kind: CheckKind::DnsMx,
        status,
        detail,
        expires_at: None,
        checked_at: Utc::now(),
    })
}