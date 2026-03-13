use anyhow::Result;
use chrono::Utc;
use reqwest::{Client, redirect::Policy};

use crate::models::{CheckResult, CheckKind, CheckStatus};

// Build a client that does NOT follow redirects so we can inspect them manually
fn build_client(follow_redirects: bool) -> Result<Client> {
    let policy = if follow_redirects {
        Policy::limited(10)
    } else {
        Policy::none()
    };

    let client = Client::builder()
        .redirect(policy)
        .danger_accept_invalid_certs(false)
        .build()?;

    Ok(client)
}

pub async fn check_hsts(domain_id: i64, fqdn: &str) -> Result<CheckResult> {
    let client = build_client(true)?;
    let url = format!("https://{}", fqdn);
    let response = client.get(&url).send().await;

    let (status, detail) = match response {
        Err(e) => (CheckStatus::Error, format!("Request failed: {}", e)),
        Ok(resp) => {
            let has_hsts = resp.headers()
                .get("strict-transport-security")
                .is_some();

            if has_hsts {
                let value = resp.headers()
                    .get("strict-transport-security")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("present");
                (CheckStatus::Ok, format!("HSTS present: {}", value))
            } else {
                (CheckStatus::Warning, "No HSTS header found".to_string())
            }
        }
    };

    Ok(CheckResult {
        id: 0,
        domain_id,
        kind: CheckKind::HttpHsts,
        status,
        detail,
        expires_at: None,
        checked_at: Utc::now(),
    })
}

pub async fn check_redirect(domain_id: i64, fqdn: &str) -> Result<CheckResult> {
    let client = build_client(false)?;
    let http_url = format!("http://{}", fqdn);
    let response = client.get(&http_url).send().await;

    let (status, detail) = match response {
        Err(e) => (CheckStatus::Error, format!("Request failed: {}", e)),
        Ok(resp) => {
            let status_code = resp.status().as_u16();
            // 301, 302, 308 is expected, check it points to https
            if status_code == 301 || status_code == 302 || status_code == 308 {
                let location = resp.headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");

                if location.starts_with("https://") {
                    (CheckStatus::Ok, format!("HTTP → HTTPS redirect confirmed ({})", status_code))
                } else {
                    (CheckStatus::Warning, format!("Redirects but not to HTTPS: {}", location))
                }
            } else {
                (CheckStatus::Critical, format!("No redirect from HTTP — status {}", status_code))
            }
        }
    };

    Ok(CheckResult {
        id: 0,
        domain_id,
        kind: CheckKind::HttpRedirect,
        status,
        detail,
        expires_at: None,
        checked_at: Utc::now(),
    })
}