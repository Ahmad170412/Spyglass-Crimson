# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| `0.2.x` (current) | ✅ |
| `< 0.2` | ❌ |

This project is pre-1.0. Security fixes land on the latest release line; there is
no long-term support branch yet.

## Reporting a Vulnerability

**Please do not open a public issue for a security problem.**

Report it privately via GitHub's security advisory form:

> **Security → Report a vulnerability** on <https://github.com/Ahmad170412/Spyglass-Crimson>

If advisories are unavailable, open a private issue or contact the maintainer
directly through the repository's owner profile.

Please include:

- A description of the issue and its impact
- Steps to reproduce, or a proof of concept
- The affected version, OS, and Python version
- Any suggested remediation

### What to expect

- **Acknowledgement** within 72 hours
- **Triage** within 7 days — assessment, severity, and a decision to fix
- **Fix and disclosure** coordinated with you, before any public write-up
- Credit in the release notes unless you prefer otherwise

Please give maintainers reasonable time to ship a fix before disclosing publicly.

## Security Boundaries

Spyglass-Crimson is designed around a few deliberate guarantees. Reports that
these are violated are treated as vulnerabilities, not feature requests.

### 1. Credentials never leave the secure store

API keys resolve in this order: environment variable → OS keyring → a `0600`
local fallback file. They are **never** written to SQLite, **never** returned by
any API endpoint, and **never** rendered back into the settings page. The
`GET /api/credentials` response reports only *whether* a key exists.

If you find a path that returns a key value, that is a high-severity bug.

### 2. The server is loopback-only

The application binds `127.0.0.1`. It is not designed to be exposed to a
network. Running it behind a reverse proxy that makes it publicly reachable is
out of scope and voids the guarantees above — in particular, there is no
authentication on the API.

### 3. Passive only

The tool queries third-party public datasets. It does not send traffic to the
target under test. Any change that would send packets to a target belongs in a
separate, explicitly authorized project — see [ETHICS.md](ETHICS.md).

### 4. Aggressive mode is gated

Active modes require a recorded, unexpired authorization entry for that exact
target, checked server-side. The UI toggle is a convenience, not the
enforcement. Bypassing the check is a vulnerability.

## Out of Scope

- Findings from running the tool against infrastructure you do not own or have
  authorization to assess
- The inherent risk of querying public datasets (RDAP, crt.sh, DNS, Wayback)
  that may return personal data — this is expected and documented
- Denial of service caused by deliberately exceeding upstream rate limits
- Vulnerabilities in third-party dependencies with no working exploit against
  this project

## Dependencies

Runtime dependencies are pinned to compatible ranges in `requirements.txt`:

| Package | Range |
|---|---|
| Flask | `>=3.0,<4` |
| httpx | `>=0.27,<1` |
| keyring | `>=25,<26` |

Run `pip list --outdated` against your environment periodically, and report
anything you believe affects this project.

---

See [ETHICS.md](ETHICS.md) for the acceptable-use policy and [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.
