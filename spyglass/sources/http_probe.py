from __future__ import annotations

import re
import time

import httpx

from spyglass.models import SourceContext, SourceError, SourceResult, Target

from ._active import primary_address, require_authorization
from .base import Source

MAX_BODY_BYTES = 64 * 1024
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)


def _read_limited(response: httpx.Response, limit: int = MAX_BODY_BYTES) -> tuple[bytes, bool]:
    buffer = bytearray()
    for chunk in response.iter_bytes():
        buffer.extend(chunk)
        if len(buffer) >= limit:
            return bytes(buffer[:limit]), True
    return bytes(buffer), False


def _title(body: bytes, charset: str | None) -> str | None:
    try:
        text = body.decode(charset or "utf-8", errors="replace")
    except LookupError:
        text = body.decode("utf-8", errors="replace")
    match = TITLE_RE.search(text)
    if not match:
        return None
    title = " ".join(match.group(1).split())
    return title[:200] or None


class HttpProbeSource(Source):
    """One authorized HTTPS request: status, headers, title, redirect target.

    This is the only source that talks to the target. It is gated server-side,
    refuses non-public address space, follows no redirects, and reads at most
    64 KiB of the response body.
    """

    id = "http"
    label = "HTTP probe"
    layer = "aggressive"
    description = "One authorized HTTPS request: status, headers, title, and redirect"
    accepts = ("domain", "ip")
    docs_url = ""

    def endpoint(self, target: Target) -> str:
        host = target.host if target.kind == "domain" else target.value
        if not host:
            raise SourceError("No host to probe")
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        return f"https://{host}/"

    def run(self, target: Target, ctx: SourceContext) -> SourceResult:
        require_authorization(ctx, target)

        host = (target.host if target.kind == "domain" else target.value) or ""
        if not host:
            raise SourceError("No host to probe")
        primary_address(host)
        url = self.endpoint(target)

        started = time.monotonic()
        headers = {
            "User-Agent": ctx.settings.user_agent,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Encoding": "identity",
        }
        try:
            with httpx.Client(
                follow_redirects=False,
                timeout=httpx.Timeout(ctx.settings.http_timeout),
                headers=headers,
                # A proxy could resolve the name differently and bypass the
                # private-address check above, so go direct.
                trust_env=False,
            ) as client:
                with client.stream("GET", url) as response:
                    body, truncated = _read_limited(response)
                    status = response.status_code
                    response_headers = response.headers
                    charset = response.charset_encoding
                    http_version = response.http_version
        except httpx.HTTPError as exc:
            raise SourceError(f"HTTP probe failed: {exc}") from exc

        elapsed_ms = int((time.monotonic() - started) * 1000)
        lowered = {key.lower(): value for key, value in response_headers.items()}
        present = {name: lowered.get(name) for name in SECURITY_HEADERS}
        payload = {
            "url": url,
            "host": host,
            "status_code": status,
            "http_version": http_version,
            "server": lowered.get("server"),
            "content_type": lowered.get("content-type"),
            "title": _title(body, charset),
            "redirect": lowered.get("location"),
            "security_headers": present,
            "missing_security_headers": [name for name, value in present.items() if not value],
            "body_bytes": len(body),
            "body_truncated": truncated,
            "elapsed_ms": elapsed_ms,
        }
        return SourceResult(
            source=self.id,
            status="ok",
            data=payload,
            record_count=1,
            provider="direct",
        )
