use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::Deserialize;

use crate::models::{CheckResult, CheckKind, CheckStatus};

// IANA bootstrap tells us which RDAP server handles a given TLD
#[derive(Debug, Deserialize)]
struct IanaBootstrap {
    services: Vec<(Vec<String>, Vec<String>)>,
}

#[derive(Debug, Deserialize)]
struct RdapResponse {
    events: Option<Vec<RdapEvent>>,
}

#[derive(Debug, Deserialize)]
struct RdapEvent {
    #[serde(rename = "eventAction")]
    event_action: String,
    #[serde(rename = "eventDate")]
    event_date: String,
}

async fn get_rdap_base_url(tld: &str, client: &Client) -> Result<String> {
    let bootstrap: IanaBootstrap = client
        .get("https://data.iana.org/rdap/dns.json")
        .send()
        .await?
        .json()
        .await?;

    for (tlds, urls) in &bootstrap.services {
        if tlds.iter().any(|t| t.eq_ignore_ascii_case(tld)) {
            if let Some(url) = urls.last() {
                return Ok(url.trim_end_matches('/').to_string());
            }
        }
    }

    Err(anyhow!("No RDAP server found for TLD: {}", tld))
}

pub async fn check_domain_expiry(domain_id: i64, fqdn: &str) -> Result<CheckResult> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    // Extract TLD from fqdn
    let tld = fqdn
        .rsplit('.')
        .next()
        .ok_or_else(|| anyhow!("Could not extract TLD from {}", fqdn))?;

    let base_url = match get_rdap_base_url(tld, &client).await {
        Ok(url) => url,
        Err(_) => {
            return Ok(CheckResult {
                id: 0,
                domain_id,
                kind: CheckKind::DomainExpiry,
                status: CheckStatus::Error,
                detail: format!("No RDAP server found for .{}", tld),
                expires_at: None,
                checked_at: Utc::now(),
            });
        }
    };

    let rdap_url = format!("{}/domain/{}", base_url, fqdn);
    let response = match client.get(&rdap_url).send().await {
        Ok(r) => r,
        Err(e) => {
            return Ok(CheckResult {
                id: 0,
                domain_id,
                kind: CheckKind::DomainExpiry,
                status: CheckStatus::Error,
                detail: format!("RDAP request failed: {}", e),
                expires_at: None,
                checked_at: Utc::now(),
            });
        }
    };

    if !response.status().is_success() {
        return Ok(CheckResult {
            id: 0,
            domain_id,
            kind: CheckKind::DomainExpiry,
            status: CheckStatus::Error,
            detail: format!("RDAP returned status {}", response.status()),
            expires_at: None,
            checked_at: Utc::now(),
        });
    }

    let rdap: RdapResponse = response.json().await
        .map_err(|e| anyhow!("Failed to parse RDAP response: {}", e))?;

    // Find expiry event
    let expiry = rdap.events
        .unwrap_or_default()
        .into_iter()
        .find(|e| e.event_action == "expiration")
        .and_then(|e| e.event_date.parse::<DateTime<Utc>>().ok());

    let now = Utc::now();

    let (status, detail) = match expiry {
        None => (CheckStatus::Error, "No expiry date found in RDAP response".to_string()),
        Some(exp) => {
            let days = (exp - now).num_days();
            match days {
                d if d < 0  => (CheckStatus::Critical, format!("Domain EXPIRED {} days ago", d.abs())),
                d if d < 14 => (CheckStatus::Critical, format!("Domain expires in {} days", d)),
                d if d < 30 => (CheckStatus::Warning,  format!("Domain expires in {} days", d)),
                d           => (CheckStatus::Ok,        format!("Domain expires in {} days", d)),
            }
        }
    };

    Ok(CheckResult {
        id: 0,
        domain_id,
        kind: CheckKind::DomainExpiry,
        status,
        detail,
        expires_at: expiry,
        checked_at: now,
    })
}