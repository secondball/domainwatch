use anyhow::Result;
use tokio::task::JoinSet;
use crate::models::CheckResult;
use crate::checks::{tls, dns, http, rdap};

pub struct RunResult {
    pub checks: Vec<CheckResult>,
    pub subdomains_ct: Vec<String>,
    pub subdomains_bf: Vec<String>,
    pub ns_records: Vec<String>,
    pub a_records: Vec<String>,
}

pub async fn run_all(domain_id: i64, fqdn: &str) -> RunResult {
    // --- Concurrent health checks ---
    let mut set: JoinSet<Result<CheckResult>> = JoinSet::new();

    let f = fqdn.to_string();
    set.spawn(async move { tls::check_tls(domain_id, &f).await });

    let f = fqdn.to_string();
    set.spawn(async move { dns::check_spf(domain_id, &f).await });

    let f = fqdn.to_string();
    set.spawn(async move { dns::check_dmarc(domain_id, &f).await });

    let f = fqdn.to_string();
    set.spawn(async move { dns::check_mx(domain_id, &f).await });

    let f = fqdn.to_string();
    set.spawn(async move { http::check_hsts(domain_id, &f).await });

    let f = fqdn.to_string();
    set.spawn(async move { http::check_redirect(domain_id, &f).await });

    let f = fqdn.to_string();
    set.spawn(async move { rdap::check_domain_expiry(domain_id, &f).await });

    let mut checks = Vec::new();
    while let Some(res) = set.join_next().await {
        match res {
            Ok(Ok(check)) => checks.push(check),
            Ok(Err(e))    => eprintln!("Check error: {}", e),
            Err(e)        => eprintln!("Task panicked: {}", e),
        }
    }

    // --- Discovery (sequential, external APIs) ---
    let subdomains_ct = crate::checks::crtsh::discover_subdomains(fqdn)
        .await
        .unwrap_or_default();

    let subdomains_bf = crate::checks::enumerate::brute_force_subdomains(fqdn)
        .await
        .unwrap_or_default();

    let ns_records = crate::checks::enumerate::get_ns_records(fqdn)
        .await
        .unwrap_or_default();

    let a_records = crate::checks::enumerate::get_a_records(fqdn)
        .await
        .unwrap_or_default();

    RunResult { checks, subdomains_ct, subdomains_bf, ns_records, a_records }
}