use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// --- Client ---
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub id: i64,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

// --- Domain ---
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Domain {
    pub id: i64,
    pub client_id: i64,
    pub fqdn: String,           // e.g. "example.com"
    pub active: bool,
    pub created_at: DateTime<Utc>,
}

// --- Check Types ---
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CheckKind {
    Tls,
    DomainExpiry,
    DnsSpf,
    DnsDmarc,
    DnsMx,
    HttpHsts,
    HttpRedirect,
}

impl std::fmt::Display for CheckKind {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CheckKind::Tls          => write!(f, "TLS"),
            CheckKind::DomainExpiry => write!(f, "DOMAIN_EXPIRY"),
            CheckKind::DnsSpf       => write!(f, "DNS_SPF"),
            CheckKind::DnsDmarc     => write!(f, "DNS_DMARC"),
            CheckKind::DnsMx        => write!(f, "DNS_MX"),
            CheckKind::HttpHsts     => write!(f, "HTTP_HSTS"),
            CheckKind::HttpRedirect => write!(f, "HTTP_REDIRECT"),
        }
    }
}

// --- Check Status ---
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CheckStatus {
    Ok,
    Warning,   // e.g. expiring in < 30 days
    Critical,  // e.g. expiring in < 7 days
    Error,     // check failed to run
}

impl std::fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CheckStatus::Ok       => write!(f, "OK"),
            CheckStatus::Warning  => write!(f, "WARNING"),
            CheckStatus::Critical => write!(f, "CRITICAL"),
            CheckStatus::Error    => write!(f, "ERROR"),
        }
    }
}

// --- Check Result ---
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub id: i64,
    pub domain_id: i64,
    pub kind: CheckKind,
    pub status: CheckStatus,
    pub detail: String,          // human readable — "Expires in 14 days", "Missing DMARC", etc.
    pub expires_at: Option<DateTime<Utc>>,  // for cert/domain expiry checks
    pub checked_at: DateTime<Utc>,
}

//--- check subdomains ---
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subdomain {
    pub id: i64,
    pub domain_id: i64,
    pub fqdn: String,
    pub source: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DiscoverySource {
    CrtSh,
    BruteForce,
    DnsNs,
}

impl std::fmt::Display for DiscoverySource {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            DiscoverySource::CrtSh      => write!(f, "crt.sh"),
            DiscoverySource::BruteForce => write!(f, "brute_force"),
            DiscoverySource::DnsNs      => write!(f, "dns_ns"),
        }
    }
}