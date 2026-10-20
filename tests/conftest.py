from __future__ import annotations

from pathlib import Path

import pytest

from spyglass import create_app
from spyglass.cache import Cache
from spyglass.config import Settings
from spyglass.db import init_db
from spyglass.http import HttpClient
from spyglass.models import SourceContext


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        db_path=tmp_path / "spyglass.db",
        instance_path=tmp_path,
        credentials_path=tmp_path / "credentials.json",
        use_keyring=False,
        http_retries=0,
    )


@pytest.fixture
def cache(settings: Settings) -> Cache:
    init_db(settings.db_path)
    return Cache(settings.db_path)


@pytest.fixture
def http(settings: Settings):
    client = HttpClient(
        timeout=5,
        user_agent="Spyglass-Test/0.2",
        retries=settings.http_retries,
    )
    yield client
    client.close()


@pytest.fixture
def ctx(settings: Settings, cache: Cache, http: HttpClient) -> SourceContext:
    return SourceContext(settings=settings, cache=cache, http=http)


@pytest.fixture
def app(settings: Settings):
    return create_app(settings)


@pytest.fixture
def api(app):
    return app.test_client()
