use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

use crate::models::{CheckResult, CheckKind, CheckStatus};

pub async fn check_tls(domain_id: i64, fqdn: &str) -> Result<CheckResult> {
    // Build TLS config using system roots
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs()? {
        roots.add(cert)?;
    }

    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    // TCP connect
    let stream = TcpStream::connect(format!("{}:443", fqdn))
        .await
        .map_err(|e| anyhow!("TCP connect failed: {}", e))?;

    // TLS handshake
    let server_name = ServerName::try_from(fqdn.to_string())
        .map_err(|_| anyhow!("Invalid server name"))?;

    let tls_stream = connector.connect(server_name, stream)
        .await
        .map_err(|e| anyhow!("TLS handshake failed: {}", e))?;

    // Pull cert from connection
    let (_, session) = tls_stream.get_ref();
    let certs = session
        .peer_certificates()
        .ok_or_else(|| anyhow!("No peer certificates found"))?;

    let raw = certs[0].as_ref();
    let (_, cert) = X509Certificate::from_der(raw)
        .map_err(|e| anyhow!("Failed to parse cert: {}", e))?;

    let now = Utc::now();

    let expiry_odt = cert.validity().not_after.to_datetime();
    let expiry: DateTime<Utc> = DateTime::from_timestamp(expiry_odt.unix_timestamp(), 0)
        .ok_or_else(|| anyhow!("Invalid expiry timestamp"))?;
    let days_left = (expiry - now).num_days();

    let (status, detail) = match days_left {
        d if d < 0  => (CheckStatus::Critical, format!("EXPIRED {} days ago", d.abs())),
        d if d < 7  => (CheckStatus::Critical, format!("Expires in {} days", d)),
        d if d < 30 => (CheckStatus::Warning,  format!("Expires in {} days", d)),
        d           => (CheckStatus::Ok,        format!("Expires in {} days", d)),
    };

    Ok(CheckResult {
        id: 0, // DB will assign this
        domain_id,
        kind: CheckKind::Tls,
        status,
        detail,
        expires_at: Some(expiry),
        checked_at: now,
    })
}