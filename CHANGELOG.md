# Changelog

All notable changes to **Spyglass-Crimson** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

Nothing yet.

---

## [1.0.0] — 2026-10-21 — “Crystal Pudding”

The first stable release. Passive OSINT for domains and
IP addresses, with a local dashboard, a REST API, and 18 registered data sources.

**Scope:** active capability is limited to three gated,
bounded modules — an HTTP probe, a top-100 TCP port scan, and curated template
checks — each requiring a recorded authorization.

### Added

- **Website recon** — domain or public URL targets across RDAP, DNS, certificate
  transparency, subdomains, and historical URLs.
- **IP recon** — IPv4, IPv6, CIDR, and ASN targets across RDAP, routing, PTR,
  InternetDB, Tor exit status, and Spamhaus DROP.
- **18 data sources** — 10 keyless core sources, 5 optional-key enrichment
  providers (Shodan, Censys, IPinfo, AlienVault OTX, urlscan.io), and 3 gated
  active modules.
- **Tor exit detection** — matches an address against the Tor Project's bulk exit
  list, cached for an hour.
- **Spamhaus DROP** — matches an address against the hijacked and
  bulletproof-hosting netblock feed, v4 and v6, parsed locally.
- **HTTP probe** — one authorized HTTPS `GET`: status, server, content type,
  title, redirect target, and missing security headers. No redirects followed,
  64 KiB body cap, non-public address space refused.
- **Port scan** — authorized `nmap` TCP connect scan of the top 100 ports on one
  host, with no OS detection, NSE scripts, UDP, or discovery sweeps; 30-second
  cap and a hard 1000-port ceiling.
- **Template checks** — authorized `nuclei` run over curated detection-oriented
  tags, excluding `dos`, `fuzz`, `intrusive`, `brute-force`, and `default-login`,
  at 20 requests per second, 30 seconds, 50 findings, with out-of-band
  interaction and redirects disabled.
- **Scanner availability** — `/api/sources` reports whether `nmap` and `nuclei`
  are installed, so the dashboard disables modules whose binary is missing.
- **Source selection** — `POST /api/runs` accepts `sources` to narrow the core
  plan; enrichment providers stay planned and derived sources still run last.
- **Aggressive opt-in** — `POST /api/runs` accepts `aggressive`, which adds the
  active modules only when an authorization covers the target; `active_sources`
  optionally narrows the run to specific modules.
- **Authorization expiry** — records carry an `expires_at`; `ttl_days` is
  accepted on `POST /api/authorizations`.
- **Per-source health** — the latest outcome and latency of every source is
  recorded and surfaced by `/api/sources`.
- **CIDR aggregation** — per-IP sources write one `source_runs` row per source
  per run, with the sampled addresses inside it.
- **Normalised entity graph**, **REST API**, **local dashboard**, **credential
  store**, **run budget**, and **TTL response cache**.

### Changed

- `SPYGLASS_MAX_CIDR_HOSTS` and `SPYGLASS_MAX_CENSYS_LOOKUPS` are now enforced
  rather than documented.
- `SPYGLASS_HTTP_RETRIES` is now honoured by sources.
- Instance directories are created `0700`; the database `0600`.
- Dashboard checkboxes send real source ids, so the selected tools match the run.
- Source counts distinguish core, enrichment, and aggressive layers; `keyless`
  counts core sources only.

### Fixed

- **Run budget could be exceeded.** A hung source was joined by the executor and
  could stretch a 1s budget to ~5s. The worker is now abandoned at the deadline
  and the run continues under its own timeout.
- Entity provenance was overwritten by later writers; it is now preserved.
- Authorizations never expired.
- `mode` was persisted as `passive` even for website runs.
- CIDR runs wrote one `source_runs` row per address, inflating source counts.

### Security

- Host-header allowlist rejects non-loopback `Host` values (DNS-rebinding guard),
  configurable via `SPYGLASS_ALLOWED_HOSTS`.
- The HTTP probe refuses any address that is not globally routable (loopback,
  RFC 1918, CGNAT, link-local, reserved), and re-checks authorization inside the
  module. The port scan and template checks apply the same refusal, run one host
  only, are invoked without a shell, and enforce time, rate, and scope caps
  independently of the caller.
- `TEMPLATES_AUTO_RELOAD` is enabled only in debug mode.
- Expired cache entries are purged at startup.
- API keys are never written to the database, never returned by any endpoint,
  and never rendered back into the settings page.
- The server binds `127.0.0.1` only; API responses use `Cache-Control: no-store`.
- The credential fallback file is created with `0600` permissions.
- `.gitignore` excludes the instance directory, so the database and credential
  store cannot be committed by accident.

### Documentation

- `ETHICS.md` rewritten for the bounded active modules: what each one does, what
  it refuses to do, and the risk the operator accepts.
- `SECURITY.md` documents the Host-header guard and the active-module boundaries.
- `README.md` — all 18 sources, the new configuration and API parameters, and
  the install instructions for the optional `nmap` and `nuclei` binaries.

---

[Unreleased]: https://github.com/Ahmad170412/Spyglass-Crimson/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Ahmad170412/Spyglass-Crimson/releases/tag/v1.0.0
