from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
VERSION = "1.0.0"


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ[name])
    except (KeyError, TypeError, ValueError):
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ[name])
    except (KeyError, TypeError, ValueError):
        return default


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off", ""}


@dataclass(frozen=True)
class Settings:
    db_path: Path
    instance_path: Path
    credentials_path: Path
    http_timeout: float = 10.0
    http_retries: int = 1
    wayback_timeout: float = 30.0
    user_agent: str = f"Spyglass-Crimson/{VERSION} (passive OSINT; local tool)"
    dns_ttl: int = 3600
    ct_ttl: int = 43200
    rdap_ttl: int = 86400
    internetdb_ttl: int = 86400
    wayback_ttl: int = 86400
    routing_ttl: int = 21600
    bootstrap_ttl: int = 86400
    tor_ttl: int = 3600
    drop_ttl: int = 86400
    authorization_ttl_days: int = 30
    allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost", "::1")
    nmap_top_ports: int = 100
    nmap_timeout: float = 30.0
    nuclei_timeout: float = 30.0
    nuclei_rate_limit: int = 20
    max_nuclei_findings: int = 50
    nuclei_exclude_tags: str = "dos,fuzz,intrusive,brute-force,default-login"
    max_ips_per_run: int = 25
    max_cidr_hosts: int = 512
    max_ct_names: int = 200
    max_ct_certs: int = 500
    max_wayback_urls: int = 500
    max_asn_prefixes: int = 100
    max_censys_lookups: int = 10
    run_budget_seconds: float = 60.0
    source_timeout: float = 20.0
    use_keyring: bool = True
    api_version: str = VERSION

    @classmethod
    def from_env(cls, project_root: Path | None = None) -> "Settings":
        root = Path(project_root or PROJECT_ROOT)
        instance = Path(os.environ.get("SPYGLASS_INSTANCE", root / "instance"))
        instance.mkdir(parents=True, exist_ok=True)
        # Run history contains the targets someone investigated; keep it private
        # to the account that created it, like the credential fallback file.
        try:
            instance.chmod(0o700)
        except OSError:
            pass
        db_path = Path(os.environ.get("SPYGLASS_DB", instance / "spyglass.db"))
        credentials_path = Path(
            os.environ.get("SPYGLASS_CREDENTIALS", instance / "credentials.json")
        )
        return cls(
            db_path=db_path,
            instance_path=instance,
            credentials_path=credentials_path,
            http_timeout=_env_float("SPYGLASS_HTTP_TIMEOUT", 10.0),
            http_retries=_env_int("SPYGLASS_HTTP_RETRIES", 1),
            wayback_timeout=_env_float("SPYGLASS_WAYBACK_TIMEOUT", 30.0),
            user_agent=os.environ.get(
                "SPYGLASS_USER_AGENT",
                f"Spyglass-Crimson/{VERSION} (passive OSINT; local tool)",
            ),
            dns_ttl=_env_int("SPYGLASS_DNS_TTL", 3600),
            ct_ttl=_env_int("SPYGLASS_CT_TTL", 43200),
            rdap_ttl=_env_int("SPYGLASS_RDAP_TTL", 86400),
            internetdb_ttl=_env_int("SPYGLASS_INTERNETDB_TTL", 86400),
            wayback_ttl=_env_int("SPYGLASS_WAYBACK_TTL", 86400),
            routing_ttl=_env_int("SPYGLASS_ROUTING_TTL", 21600),
            bootstrap_ttl=_env_int("SPYGLASS_BOOTSTRAP_TTL", 86400),
            tor_ttl=_env_int("SPYGLASS_TOR_TTL", 3600),
            drop_ttl=_env_int("SPYGLASS_DROP_TTL", 86400),
            authorization_ttl_days=_env_int("SPYGLASS_AUTHORIZATION_TTL", 30),
            allowed_hosts=tuple(
                host.strip().lower()
                for host in os.environ.get(
                    "SPYGLASS_ALLOWED_HOSTS", "127.0.0.1,localhost,::1"
                ).split(",")
                if host.strip()
            ),
            nmap_top_ports=_env_int("SPYGLASS_NMAP_TOP_PORTS", 100),
            nmap_timeout=_env_float("SPYGLASS_NMAP_TIMEOUT", 30.0),
            nuclei_timeout=_env_float("SPYGLASS_NUCLEI_TIMEOUT", 30.0),
            nuclei_rate_limit=_env_int("SPYGLASS_NUCLEI_RATE_LIMIT", 20),
            max_nuclei_findings=_env_int("SPYGLASS_MAX_NUCLEI_FINDINGS", 50),
            nuclei_exclude_tags=os.environ.get(
                "SPYGLASS_NUCLEI_EXCLUDE_TAGS",
                "dos,fuzz,intrusive,brute-force,default-login",
            ),
            max_ips_per_run=_env_int("SPYGLASS_MAX_IPS", 25),
            max_cidr_hosts=_env_int("SPYGLASS_MAX_CIDR_HOSTS", 512),
            max_ct_names=_env_int("SPYGLASS_MAX_CT_NAMES", 200),
            max_ct_certs=_env_int("SPYGLASS_MAX_CT_CERTS", 500),
            max_wayback_urls=_env_int("SPYGLASS_MAX_WAYBACK_URLS", 500),
            max_asn_prefixes=_env_int("SPYGLASS_MAX_ASN_PREFIXES", 100),
            max_censys_lookups=_env_int("SPYGLASS_MAX_CENSYS_LOOKUPS", 10),
            run_budget_seconds=_env_float("SPYGLASS_RUN_BUDGET", 60.0),
            source_timeout=_env_float("SPYGLASS_SOURCE_TIMEOUT", 20.0),
            use_keyring=_env_bool("SPYGLASS_KEYRING", True),
        )
