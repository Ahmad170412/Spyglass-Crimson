from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from .cache import Cache
from .config import PROJECT_ROOT, Settings
from .db import init_db

__all__ = ["create_app"]


def _request_host(host_header: str) -> str:
    """Strip the port (and IPv6 brackets) from a Host header."""
    host = (host_header or "").strip().lower()
    if host.startswith("["):
        end = host.find("]")
        return host[1:end] if end != -1 else host
    return host.split(":")[0]


def _debug_enabled() -> bool:
    """Flask applies FLASK_DEBUG after the factory runs, so read it here."""
    return os.environ.get("FLASK_DEBUG", "").strip().lower() not in {"", "0", "false", "no"}


def create_app(settings: Settings | None = None) -> Flask:
    root = Path(PROJECT_ROOT)
    app = Flask(
        __name__,
        template_folder=str(root / "templates"),
        static_folder=str(root / "static"),
    )
    app.config["TEMPLATES_AUTO_RELOAD"] = _debug_enabled()
    app.config["SPYGLASS_SETTINGS"] = settings or Settings.from_env(root)
    active: Settings = app.config["SPYGLASS_SETTINGS"]
    app.extensions["spyglass_settings"] = active
    init_db(active.db_path)
    Cache(active.db_path).purge_expired()

    from .api import bp as api_bp

    app.register_blueprint(api_bp)

    @app.before_request
    def _enforce_loopback_host():
        """Reject requests whose Host header is not a loopback name.

        Binding to 127.0.0.1 stops other machines from reaching the app, but a
        malicious page can still point a DNS name at 127.0.0.1 and reach it
        from the browser (DNS rebinding). Checking the Host header closes that.
        """
        if _request_host(request.host) not in active.allowed_hosts:
            return jsonify({"error": "unexpected Host header"}), 400
        return None

    @app.get("/")
    def index():
        return render_template("index.html")

    return app
