from __future__ import annotations

from .cache import Cache
from .config import Settings
from .http import HttpClient
from .models import SourceContext


def build_context(settings: Settings) -> SourceContext:
    return SourceContext(
        settings=settings,
        cache=Cache(settings.db_path),
        http=HttpClient(
            timeout=settings.http_timeout,
            user_agent=settings.user_agent,
            retries=settings.http_retries,
        ),
    )


def close_context(ctx: SourceContext) -> None:
    ctx.http.close()
