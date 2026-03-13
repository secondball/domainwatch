use anyhow::Result;
use reqwest::Client;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CrtShEntry {
    name_value: String,
}

pub async fn discover_subdomains(fqdn: &str) -> Result<Vec<String>> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let url = format!("https://crt.sh/?q=%.{}&output=json", fqdn);

    let response = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) if e.is_timeout() => {
            println!("  crt.sh timed out, skipping CT logs");
            return Ok(Vec::new());
        }
        Err(e) => return Err(e.into()),
    };

    if !response.status().is_success() {
        println!("  crt.sh returned status {}, skipping CT logs", response.status());
        return Ok(Vec::new());
    }

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    if !content_type.contains("json") {
        println!("  crt.sh returned non-JSON response, skipping CT logs");
        return Ok(Vec::new());
    }

    let entries: Vec<CrtShEntry> = response.json().await?;

    let mut subdomains: Vec<String> = entries
        .into_iter()
        .flat_map(|e| {
            e.name_value
                .split('\n')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty() && s.ends_with(fqdn))
                .filter(|s| !s.starts_with("*."))
                .collect::<Vec<_>>()
        })
        .collect();

    subdomains.sort();
    subdomains.dedup();

    Ok(subdomains)
}