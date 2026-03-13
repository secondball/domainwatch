# ﻿domainexplorer v0.1

A domain health monitoring tool for MSPs and sysadmins. 
Point it at a domain and it checks 
certs, 
DNS, 
HTTP configuration, 
exposed subdomains (kind of, im working on false positives)

## What it checks

- TLS certificate expiry
- Domain registration expiry (via RDAP)
- SPF, DMARC, and MX records
- HTTPS redirect and HSTS header
- Subdomains via certificate transparency logs (crt.sh) and DNS brute force

Results are stored locally in SQLite so you can track changes over time.

## Why

Most of these checks exist as separate tools. 
This runs all of them at once, stores history, 
and puts everything on one screen. 
Useful for a quick posture check on a client domain 
or keeping tabs on a portfolio of domains over time.

## Built with

- Rust
- SQLite via sqlx
- hickory-resolver, rustls, reqwest

## Usage

Enter a domain, press Enter. Results populate in place. 
[i] to scan a new domain
[r] to rescan the current one

