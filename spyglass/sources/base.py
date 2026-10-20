from __future__ import annotations

from spyglass.models import SourceContext, SourceResult, Target


class Source:
    id: str = ""
    label: str = ""
    layer: str = "core"
    description: str = ""
    accepts: tuple[str, ...] = ()
    requires_key: bool = False
    implemented: bool = True
    derived_from: tuple[str, ...] = ()
    docs_url: str = ""
    key_env: str | None = None

    def accepts_target(self, target: Target) -> bool:
        return target.kind in self.accepts

    def run(self, target: Target, ctx: SourceContext) -> SourceResult:
        raise NotImplementedError
