from __future__ import annotations

import httpx

from spyglass.cache import make_key
from spyglass.credentials import CredentialStore
from spyglass.models import SourceContext, SourceError, SourceResult, Target

from .base import Source


class KeyedSource(Source):
    """Base for enrichment adapters that require an API key.

    Subclasses set ``provider`` (the credential-store name) and override
    ``auth_headers`` / ``auth_params`` for the provider's auth scheme, plus
    ``request_url`` / ``request_params`` and ``normalize`` to shape results.
    """

    provider: str = ""

    def credentials(self, ctx: SourceContext) -> CredentialStore:
        return CredentialStore(
            ctx.settings.credentials_path, use_keyring=ctx.settings.use_keyring
        )

    def api_key(self, ctx: SourceContext) -> str:
        key = self.credentials(ctx).get(self.provider)
        if not key:
            raise SourceError(f"No {self.provider} API key configured")
        return key

    def auth_headers(self, key: str) -> dict[str, str]:
        return {}

    def auth_params(self, key: str) -> dict[str, str]:
        return {}

    def cache_key(self, target: Target) -> str:
        return make_key(self.id, target.value)

    def ttl(self, ctx: SourceContext) -> int:
        return ctx.settings.routing_ttl

    def request_url(self, target: Target) -> str:
        raise NotImplementedError

    def request_params(self, target: Target) -> dict[str, str] | None:
        return None

    def normalize(self, target: Target, payload: object) -> SourceResult:
        raise NotImplementedError

    def fetch(
        self, target: Target, ctx: SourceContext, key: str
    ) -> httpx.Response:
        return ctx.http.get(
            self.request_url(target),
            params=self.request_params(target),
            headers=self.auth_headers(key),
            timeout=self.timeout(ctx),
        )

    def timeout(self, ctx: SourceContext) -> float | None:
        return None

    def run(self, target: Target, ctx: SourceContext) -> SourceResult:
        if not self.accepts_target(target):
            raise SourceError(f"{self.label} does not accept {target.kind} targets")
        key = self.api_key(ctx)
        cache_key = self.cache_key(target)
        cached = ctx.cache.get(cache_key)
        if isinstance(cached, dict):
            return self.result_from_cache(cached)

        response = self.fetch(target, ctx, key)
        self._check_status(response)
        try:
            payload = response.json()
        except ValueError as exc:
            raise SourceError(f"{self.label} returned invalid JSON") from exc

        result = self.normalize(target, payload)
        ctx.cache.set(cache_key, result.data, self.ttl(ctx))
        return result

    def result_from_cache(self, data: dict) -> SourceResult:
        return SourceResult(
            source=self.id,
            status=str(data.get("status") or "ok"),
            data=data,
            record_count=int(data.get("record_count") or 0),
            provider=self.label,
        )

    def _check_status(self, response: httpx.Response) -> None:
        code = response.status_code
        if code == 404:
            return
        if code in {401, 403}:
            raise SourceError(
                f"{self.label} rejected the API key (HTTP {code})", retryable=False
            )
        if code == 429:
            raise SourceError(f"{self.label} rate limit hit (HTTP 429)", retryable=True)
        if code == 402:
            raise SourceError(
                f"{self.label} quota exhausted (HTTP 402)", retryable=False
            )
        if code >= 400:
            raise SourceError(f"{self.label} returned HTTP {code}")

    def test_key(self, ctx: SourceContext) -> tuple[bool, str]:
        """Cheap validation call used by the Settings screen's Test action."""
        raise NotImplementedError
