# Changelog

All notable changes to **Spyglass-Crimson** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

Nothing yet.

---

## [0.2.0] — Unreleased

The first public-facing release. Passive OSINT for domains and IP addresses,
with a local dashboard, a REST API, and 13 registered data sources.

### Added

- **Website recon** — domain or public URL targets across RDAP, DNS, certificate
  transparency, subdomains, and historical URLs.
- **IP recon** — IPv4, IPv6, CIDR, and ASN targets across RDAP, routing, PTR,
  and the keyless Shodan InternetDB dataset.
- **13 data sources** — 8 keyless core sources and 5 optional-key enrichment
  providers (Shodan, Censys, IPinfo, AlienVault OTX, urlscan.io).
- **Normalised entity graph** — `hostname`, `ip`, `certificate`, `registration`,
  `dns`, `asn`, `host`, and `enrichment` entities extracted from every source.
- **REST API** — run lifecycle (`POST /api/runs`), run results
  (`GET /api/runs/<id>/results`), source registry, and credential management.
- **Local dashboard** — Overview, Website, IP, Settings, and Results views with
  live run progress and per-source status.
- **Credential store** — provider keys resolve from environment → OS keyring →
  a `0600` fallback file, never enter SQLite, and are never returned by the API.
- **Run budget** — a configurable wall-clock budget caps every run; sources that
  exceed it are recorded as errors rather than silently retried.
- **TTL response cache** — per-source caching in SQLite keeps repeat lookups
  fast and reduces load on upstream public APIs.
- **Aggressive-mode authorization gate** — active modes require a recorded,
  unexpired authorization for that exact target.
- **Local dashboard typography** — Space Grotesk for headings, Geist Mono for
  supporting text.

### Security

- API keys are never written to the database, never returned by any endpoint,
  and never rendered back into the settings page.
- The server binds `127.0.0.1` only.
- API responses are sent with `Cache-Control: no-store`.
- The credential fallback file is created with `0600` permissions.
- `.gitignore` excludes the instance directory, so the database and credential
  store cannot be committed by accident.

### Documentation

- `ETHICS.md` — acceptable-use policy covering authorization, the passive-only
  boundary, data handling, and prohibited uses.
- `SECURITY.md` — how to report a vulnerability.
- `CONTRIBUTING.md` — contribution guidelines.

---

[Unreleased]: https://github.com/Ahmad170412/Spyglass-Crimson/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Ahmad170412/Spyglass-Crimson/releases/tag/v0.2.0
