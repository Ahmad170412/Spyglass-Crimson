from __future__ import annotations

import json
import subprocess
from typing import Any

from spyglass.models import SourceContext, SourceError, SourceResult, Target

from ._active import public_addresses, require_authorization, require_binary
from .base import Source

# Only detection-oriented template families run by default. Exploit, fuzzing,
# brute-force, DoS, and default-login templates are excluded below as well, so a
# run stays a bounded check rather than an attack.
TEMPLATE_TAGS = "cve,exposure,misconfig,tech,headers,ssl"

# Severity values nuclei emits, mapped onto what the storage layer understands.
SEVERITIES = ("info", "low", "medium", "high", "critical")


class NucleiSource(Source):
    """Rate-limited template checks against one authorized host.

    Bounded by a curated tag set, an excluded-tag list, a request rate limit, a
    hard timeout, and a finding cap. Out-of-band interaction is disabled so the
    scanner cannot be used as a callback channel. Invoked as an argument list —
    never through a shell.
    """

    id = "nuclei"
    label = "Template checks"
    layer = "aggressive"
    description = "Rate-limited, non-intrusive template checks on one authorized host"
    accepts = ("domain", "ip")
    docs_url = "https://docs.projectdiscovery.io/tools/nuclei/overview"

    def target_url(self, target: Target) -> str:
        host = target.host if target.kind == "domain" else str(target.ip)
        if not host:
            raise SourceError("No host to check")
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        return f"https://{host}/"

    def target_host(self, target: Target) -> str:
        host = target.host if target.kind == "domain" else str(target.ip)
        if not host:
            raise SourceError("No host to check")
        if target.kind == "ip" and target.ip is not None and not target.ip.is_global:
            raise SourceError(f"Refusing to scan non-public address {target.ip}")
        public_addresses(host)
        return host

    def command(
        self,
        binary: str,
        url: str,
        *,
        rate_limit: int,
        timeout: float,
        exclude_tags: str,
        user_agent: str,
    ) -> list[str]:
        command = [
            binary,
            "-u",
            url,
            "-jsonl",
            "-silent",
            "-nc",
            "-duc",
            "-no-interactsh",
            "-disable-redirects",
            "-tags",
            TEMPLATE_TAGS,
            "-severity",
            ",".join(SEVERITIES),
            "-rate-limit",
            str(rate_limit),
            "-timeout",
            str(max(1, int(timeout))),
            "-retries",
            "0",
            "-H",
            f"User-Agent: {user_agent}",
        ]
        tags = exclude_tags.strip()
        if tags:
            command += ["-etags", tags]
        return command

    def run(self, target: Target, ctx: SourceContext) -> SourceResult:
        require_authorization(ctx, target)

        host = self.target_host(target)
        url = self.target_url(target)
        binary = require_binary("nuclei", "nuclei")

        timeout = max(1.0, float(ctx.settings.nuclei_timeout))
        rate_limit = max(1, min(int(ctx.settings.nuclei_rate_limit), 100))
        max_findings = max(1, int(ctx.settings.max_nuclei_findings))

        command = self.command(
            binary,
            url,
            rate_limit=rate_limit,
            timeout=timeout,
            exclude_tags=ctx.settings.nuclei_exclude_tags,
            user_agent=ctx.settings.user_agent,
        )
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout + 10,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise SourceError(
                f"nuclei timed out after {timeout + 10:.0f}s "
                "(first run may be downloading templates; run `nuclei -update-templates` once)"
            ) from exc
        except OSError as exc:
            raise SourceError(f"Could not execute nuclei: {exc}") from exc

        if completed.returncode != 0 and not (completed.stdout or "").strip():
            stderr = (completed.stderr or "").strip().splitlines()
            reason = stderr[-1] if stderr else f"exit code {completed.returncode}"
            raise SourceError(f"nuclei failed: {reason}")

        findings, truncated = self.parse(completed.stdout, max_findings)
        payload: dict[str, Any] = {
            "url": url,
            "host": host,
            "findings": findings,
            "finding_count": len(findings),
            "truncated": truncated,
            "rate_limit": rate_limit,
            "tags": TEMPLATE_TAGS.split(","),
            "scanner": "nuclei",
        }
        return SourceResult(
            source=self.id,
            status="ok" if findings else "empty",
            data=payload,
            record_count=len(findings),
            provider="nuclei",
        )

    def parse(self, output: str, limit: int) -> tuple[list[dict[str, Any]], bool]:
        findings: list[dict[str, Any]] = []
        for line in output.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if not isinstance(item, dict):
                continue
            info = item.get("info") or {}
            severity = str(info.get("severity") or "info").lower()
            if severity not in SEVERITIES:
                severity = "info"
            tags = info.get("tags") or []
            if isinstance(tags, str):
                tags = [tag.strip() for tag in tags.split(",") if tag.strip()]
            findings.append(
                {
                    "template": str(
                        item.get("template-id") or item.get("templateID") or ""
                    ),
                    "name": str(info.get("name") or ""),
                    "severity": severity,
                    "matched_at": str(item.get("matched-at") or item.get("host") or ""),
                    "type": str(item.get("type") or ""),
                    "tags": list(tags),
                }
            )
            if len(findings) >= limit:
                return findings, True
        return findings, False
