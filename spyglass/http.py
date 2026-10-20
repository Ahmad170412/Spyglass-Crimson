from __future__ import annotations

import time
from typing import Any

import httpx

from .cache import Cache, make_key


class HttpClient:
    def __init__(
        self,
        *,
        timeout: float = 10.0,
        user_agent: str = "Spyglass-Crimson/0.2",
        retries: int = 1,
    ):
        self.retries = max(0, retries)
        self._client = httpx.Client(
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
            headers={
                "User-Agent": user_agent,
                "Accept": "application/json",
            },
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def get(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> httpx.Response:
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                if timeout is None:
                    response = self._client.get(url, params=params, headers=headers)
                else:
                    response = self._client.get(
                        url, params=params, headers=headers, timeout=timeout
                    )
            except httpx.TransportError as exc:
                last_error = exc
                if attempt < self.retries:
                    time.sleep(0.25 * (attempt + 1))
                    continue
                raise
            if response.status_code in {429, 500, 502, 503, 504} and attempt < self.retries:
                retry_after = response.headers.get("Retry-After")
                try:
                    delay = min(float(retry_after), 2.0) if retry_after else 0.35
                except (TypeError, ValueError):
                    delay = 0.35
                time.sleep(delay * (attempt + 1))
                continue
            return response
        if last_error is not None:
            raise last_error
        raise RuntimeError("HTTP request failed without a response")

    def get_json(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        cache: Cache | None = None,
        ttl: int | None = None,
        cache_key: str | None = None,
        timeout: float | None = None,
    ) -> Any:
        if cache is not None and cache_key:
            cached = cache.get(cache_key)
            if cached is not None:
                return cached
        response = self.get(url, params=params, headers=headers, timeout=timeout)
        response.raise_for_status()
        data = response.json()
        if cache is not None and cache_key and ttl:
            cache.set(cache_key, data, ttl)
        return data

    def get_text(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> str:
        response = self.get(url, params=params, headers=headers)
        response.raise_for_status()
        return response.text


def cached_json(
    client: HttpClient,
    cache: Cache,
    url: str,
    *,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    ttl: int = 3600,
) -> Any:
    key = make_key("http", url, repr(sorted((params or {}).items())))
    return client.get_json(
        url,
        params=params,
        headers=headers,
        cache=cache,
        ttl=ttl,
        cache_key=key,
    )
