mod db;
mod models;
mod checks;
mod ui;

use anyhow::Result;
use ui::AppState;

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install crypto provider");

    let pool = db::connect("certwatch.db").await?;
    db::migrate(&pool).await?;

    let mut state = AppState::new();

    loop {
        state = ui::run_ui(state).map_err(|e| anyhow::anyhow!(e))?;

        // User pressed q
        if !state.scanning {
            break;
        }

        // Empty target guard
        if state.target.trim().is_empty() {
            state.scanning = false;
            continue;
        }

        let fqdn = state.target.clone();
        state.checks.clear();
        state.subdomains.clear();
        state.ns_records.clear();
        state.a_records.clear();
        state.subdomain_scroll = 0;

        let client_id = db::insert_client(&pool, "Default").await?;
        let domain_id = db::insert_domain(&pool, client_id, &fqdn).await?;

        let run = checks::runner::run_all(domain_id, &fqdn).await;

        for result in &run.checks {
            db::save_result(&pool, result).await?;
        }
        for sub in &run.subdomains_ct {
            db::upsert_subdomain(&pool, domain_id, sub, "crt.sh").await?;
        }
        for sub in &run.subdomains_bf {
            db::upsert_subdomain(&pool, domain_id, sub, "brute_force").await?;
        }

        let mut all_subs = run.subdomains_ct.clone();
        all_subs.extend(run.subdomains_bf.clone());
        all_subs.sort();
        all_subs.dedup();

        state.checks = run.checks;
        state.subdomains = all_subs;
        state.ns_records = run.ns_records;
        state.a_records = run.a_records;
        state.scanning = false;
        state.input_mode = false;
    }

    Ok(())
}