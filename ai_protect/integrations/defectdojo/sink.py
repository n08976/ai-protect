"""DefectDojoSink — the FindingsSink implementation backed by the REST client.

Derives the DefectDojo product / engagement / test from (in order):
    1. explicit values on the SinkContext
    2. UI settings defaults (defectdojo_product / defectdojo_engagement)
    3. sensible defaults from the scan provenance (app name, stage)
"""
from __future__ import annotations

from ...core.findings import Finding
from ..base import FindingsSink, SinkContext, SinkNotConfigured, SinkResult
from .client import DefectDojoClient, DefectDojoError
from .config import DefectDojoConfig, _settings_get
from .serialize import filter_by_severity


class DefectDojoSink(FindingsSink):
    name = "defectdojo"
    label = "DefectDojo"

    def __init__(self, config: DefectDojoConfig | None = None, *, session=None,
                 reimport: bool = True, min_severity: str = "", product_type: str = ""):
        self._config = config if config is not None else DefectDojoConfig.resolve()
        self._session = session
        self.reimport = reimport
        self.min_severity = min_severity or _settings_get("defectdojo_min_severity", "info") or "info"
        self.product_type = product_type or _settings_get("defectdojo_product_type", "ai-protect") or "ai-protect"

    def is_configured(self) -> bool:
        return self._config is not None

    def _product(self, ctx: SinkContext) -> str:
        return ctx.product or _settings_get("defectdojo_product") or ctx.app_name or "ai-protect"

    def _engagement(self, ctx: SinkContext) -> str:
        if ctx.engagement:
            return ctx.engagement
        configured = _settings_get("defectdojo_engagement")
        if configured:
            return configured
        return f"ai-protect {ctx.stage}".strip() if ctx.stage else "ai-protect pipeline"

    def _test_title(self, ctx: SinkContext) -> str:
        return ctx.test_title or (f"ai-protect {ctx.stage}".strip() if ctx.stage else "ai-protect")

    def push(self, findings: list[Finding], ctx: SinkContext) -> SinkResult:
        if self._config is None:
            raise SinkNotConfigured(
                "DefectDojo is not configured (set DEFECTDOJO_URL + DEFECTDOJO_API_TOKEN, "
                "or configure it under /settings).")
        if self.min_severity and self.min_severity != "info":
            findings = filter_by_severity(findings, self.min_severity)
        product = self._product(ctx)
        engagement = self._engagement(ctx)
        client = DefectDojoClient(self._config, session=self._session)
        try:
            res = client.push(
                findings, product=product, engagement=engagement,
                product_type=self.product_type,
                test_title=self._test_title(ctx), reimport=self.reimport,
                minimum_severity=(self.min_severity or "info").capitalize())
        except DefectDojoError as e:
            return SinkResult(sink=self.name, ok=False, detail=str(e),
                              ref={"product": product, "engagement": engagement})
        ref = {"product": product, "engagement": engagement}
        for k in ("test", "test_id", "engagement_id", "product_id"):
            if isinstance(res, dict) and res.get(k):
                ref[k] = res[k]
        return SinkResult(
            sink=self.name, ok=True, pushed=len(findings),
            detail=f"product={product!r} engagement={engagement!r}", ref=ref)
