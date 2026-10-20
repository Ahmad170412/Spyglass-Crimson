from __future__ import annotations

from pathlib import Path

from flask import Flask, render_template

from .config import PROJECT_ROOT, Settings
from .db import init_db

__all__ = ["create_app"]


def create_app(settings: Settings | None = None) -> Flask:
    root = Path(PROJECT_ROOT)
    app = Flask(
        __name__,
        template_folder=str(root / "templates"),
        static_folder=str(root / "static"),
    )
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SPYGLASS_SETTINGS"] = settings or Settings.from_env(root)
    active: Settings = app.config["SPYGLASS_SETTINGS"]
    app.extensions["spyglass_settings"] = active
    init_db(active.db_path)

    from .api import bp as api_bp

    app.register_blueprint(api_bp)

    @app.get("/")
    def index():
        return render_template("index.html")

    return app
