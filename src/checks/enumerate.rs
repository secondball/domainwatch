use anyhow::Result;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::*;

// Common subdomains worth checking for MSP targets
const WORDLIST: &[&str] = &[
    "www", "mail", "remote", "vpn", "webmail", "portal", "admin",
    "autodiscover", "lyncdiscover", "sip", "ftp", "ssh", "rdp",
    "citrix", "exchange", "owa", "smtp", "imap", "pop", "api",
    "dev", "staging", "test", "backup", "monitor", "helpdesk",
];

pub async fn brute_force_subdomains(fqdn: &str) -> Result<Vec<String>> {
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::cloudflare(),
        ResolverOpts::default(),
    );

    // Detect wildcard — if this resolves, filter its IPs from results
    let canary = format!("thissubdomainshouldnotexist12345.{}", fqdn);
    let wildcard_ips: Vec<String> = resolver
        .lookup_ip(canary.as_str())
        .await
        .map(|r| r.iter().map(|ip| ip.to_string()).collect())
        .unwrap_or_default();

    if !wildcard_ips.is_empty() {
        println!("  Wildcard DNS detected ({}), filtering brute force results", wildcard_ips.join(", "));
    }

    let mut found = Vec::new();

    for prefix in WORDLIST {
        let candidate = format!("{}.{}", prefix, fqdn);
        if let Ok(result) = resolver.lookup_ip(candidate.as_str()).await {
            let ips: Vec<String> = result.iter().map(|ip| ip.to_string()).collect();
            // Only keep if it resolves to different IPs than the wildcard
            let is_wildcard = ips.iter().all(|ip| wildcard_ips.contains(ip));
            if !is_wildcard {
                found.push(candidate);
            }
        }
    }

    Ok(found)
}

pub async fn get_ns_records(fqdn: &str) -> Result<Vec<String>> {
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::cloudflare(),
        ResolverOpts::default(),
    );

    let lookup = resolver.ns_lookup(fqdn).await?;
    let records = lookup
        .iter()
        .map(|ns| ns.to_string().trim_end_matches('.').to_string())
        .collect();

    Ok(records)
}

pub async fn get_a_records(fqdn: &str) -> Result<Vec<String>> {
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::cloudflare(),
        ResolverOpts::default(),
    );

    let lookup = resolver.lookup_ip(fqdn).await?;
    let records = lookup
        .iter()
        .map(|ip| ip.to_string())
        .collect();

    Ok(records)
}