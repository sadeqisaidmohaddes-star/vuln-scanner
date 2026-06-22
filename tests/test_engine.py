"""Engine-level tests for :class:`vulnscan.core.engine.ScanEngine`.

These tests exercise the orchestrator in isolation from the real scanner modules
and the network. Each test defines tiny in-file :class:`ScannerModule` subclasses
whose ``run`` methods return canned findings (or raise), so nothing here touches a
socket. The engine still spins up its own ``httpx.AsyncClient`` — that is fine, the
fake modules simply never use ``ctx.http``.

Covered behaviours:

* a normal module produces a HIGH finding for a ``127.0.0.1`` target;
* duplicate findings (same ``module|target|title``) collapse to one;
* a module that raises is isolated — the scan completes, other modules' findings
  survive, and the failure is recorded in ``result.errors``;
* intrusive modules are skipped under ``passive=True`` and run under ``passive=False``;
* findings come back severity-sorted (highest first) and ``exit_code()`` reflects
  the highest severity;
* ``select_modules`` filters by explicit name and by passive mode;
* an empty result is built when there are no modules and no targets.

Tests are ``async def`` and rely on ``asyncio_mode = "auto"`` (configured in
``pyproject.toml``), so no ``@pytest.mark.asyncio`` decorator is needed.
"""
from __future__ import annotations

from vulnscan import Finding, ScanConfig, ScannerModule, Scope, Severity, Target
from vulnscan.core.engine import ScanEngine
from vulnscan.core.models import EXIT_CODES

# --------------------------------------------------------------------------------------
# Fakes: in-file ScannerModule subclasses that never touch the network.
# --------------------------------------------------------------------------------------

GOOD_TITLE = "Example high-severity finding"


class GoodModule(ScannerModule):
    """Returns exactly one HIGH finding for every target it sees."""

    name = "good"
    description = "test: emits one HIGH finding"
    category = "test"
    default_severity = Severity.HIGH

    async def run(self, target: Target, ctx) -> list[Finding]:
        return [
            self.finding(
                title=GOOD_TITLE,
                severity=Severity.HIGH,
                description="A high finding from the good test module.",
                target=target,
            )
        ]


class DupModule(ScannerModule):
    """Emits a finding that is byte-for-byte identical (for dedup) to GoodModule's.

    The dedupe key is ``(module, target, title)`` (see ``Finding.dedupe_key``), so to
    produce a *true* duplicate this module attributes its finding to ``"good"`` (the
    same module name GoodModule uses) with the same title and target. The engine must
    collapse the two into a single finding.
    """

    name = "dup"
    description = "test: emits a duplicate of GoodModule's finding"
    category = "test"

    async def run(self, target: Target, ctx) -> list[Finding]:
        return [
            Finding(
                title=GOOD_TITLE,
                severity=Severity.HIGH,
                description="Same logical finding, different wording.",
                target=str(target),
                module="good",  # match GoodModule so (module, target, title) collides
            )
        ]


class BoomModule(ScannerModule):
    """Always raises from ``run`` to verify per-module isolation."""

    name = "boom"
    description = "test: raises to verify isolation"
    category = "test"

    async def run(self, target: Target, ctx) -> list[Finding]:
        raise RuntimeError("intentional boom from BoomModule")


class IntrusiveModule(ScannerModule):
    """An intrusive module: skipped under ``--passive``, run otherwise."""

    name = "intrusive"
    description = "test: intrusive, emits a CRITICAL finding"
    category = "test"
    intrusive = True
    default_severity = Severity.CRITICAL

    async def run(self, target: Target, ctx) -> list[Finding]:
        return [
            self.finding(
                title="Intrusive critical finding",
                severity=Severity.CRITICAL,
                description="Only present when intrusive modules are allowed to run.",
                target=target,
            )
        ]


class LowModule(ScannerModule):
    """Emits a single LOW finding (used to check severity ordering)."""

    name = "low"
    description = "test: emits one LOW finding"
    category = "test"
    default_severity = Severity.LOW

    async def run(self, target: Target, ctx) -> list[Finding]:
        return [
            self.finding(
                title="A low-severity finding",
                severity=Severity.LOW,
                description="Low.",
                target=target,
            )
        ]


# --------------------------------------------------------------------------------------
# Scope / config helpers.
# --------------------------------------------------------------------------------------

def make_scope(targets: list[str] | None = None) -> Scope:
    """Build an authorized scope over the given targets (default: 127.0.0.1)."""
    return Scope.from_dict(
        {
            "authorization": {
                "authorized": True,
                "authorized_by": "Test Harness",
                "engagement_id": "TEST-0001",
            },
            "scope": {"targets": targets if targets is not None else ["127.0.0.1"]},
        }
    )


def make_config(*, passive: bool = False) -> ScanConfig:
    # Keep concurrency/rate generous so the tiny fake modules run without waiting.
    return ScanConfig(rate_limit=1000.0, concurrency=50, timeout=1.0, passive=passive)


# --------------------------------------------------------------------------------------
# Sanity: scope resolution for 127.0.0.1.
# --------------------------------------------------------------------------------------

def test_scope_resolves_loopback_target() -> None:
    scope = make_scope()
    assert scope.is_in_scope("127.0.0.1") is True
    targets = scope.targets()
    assert len(targets) == 1
    assert targets[0].host == "127.0.0.1"
    # str(Target) is what findings carry; confirm it for the dedup-key assertions.
    assert str(targets[0]) == "127.0.0.1"


# --------------------------------------------------------------------------------------
# Happy path: one HIGH finding, exit code reflects it.
# --------------------------------------------------------------------------------------

async def test_good_module_produces_one_high_finding() -> None:
    engine = ScanEngine(make_scope(), make_config(), [GoodModule()])
    result = await engine.run()

    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity is Severity.HIGH
    assert f.module == "good"
    assert f.target == "127.0.0.1"
    assert f.title == GOOD_TITLE

    assert result.errors == []
    assert result.targets_scanned == 1
    assert result.modules_run == ["good"]
    assert result.highest is Severity.HIGH
    assert result.exit_code() == EXIT_CODES[Severity.HIGH] == 30


# --------------------------------------------------------------------------------------
# Dedup: identical (module, target, title) collapses to one finding.
# --------------------------------------------------------------------------------------

async def test_duplicate_findings_are_deduplicated() -> None:
    engine = ScanEngine(make_scope(), make_config(), [GoodModule(), DupModule()])
    result = await engine.run()

    # GoodModule and DupModule both emit module="good", same title, same target.
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.dedupe_key == ("good", "127.0.0.1", GOOD_TITLE)
    # Both modules executed even though their output collapsed.
    assert set(result.modules_run) == {"good", "dup"}
    assert result.errors == []


# --------------------------------------------------------------------------------------
# Module isolation: a raising module never aborts the scan.
# --------------------------------------------------------------------------------------

async def test_failing_module_is_isolated() -> None:
    engine = ScanEngine(make_scope(), make_config(), [GoodModule(), BoomModule()])
    result = await engine.run()

    # The good module's finding still made it through.
    assert len(result.findings) == 1
    assert result.findings[0].module == "good"

    # Both modules were scheduled; the failure is captured, not raised.
    assert set(result.modules_run) == {"good", "boom"}
    assert len(result.errors) == 1
    err = result.errors[0]
    assert err["module"] == "boom"
    assert err["target"] == "127.0.0.1"
    assert "RuntimeError" in err["error"]
    assert "intentional boom" in err["error"]


# --------------------------------------------------------------------------------------
# Passive mode: intrusive modules skipped; non-intrusive still run.
# --------------------------------------------------------------------------------------

async def test_intrusive_module_skipped_in_passive_mode() -> None:
    engine = ScanEngine(make_scope(), make_config(passive=True), [GoodModule(), IntrusiveModule()])
    result = await engine.run()

    # Intrusive module was dropped before execution.
    assert "intrusive" not in result.modules_run
    assert result.modules_run == ["good"]
    assert all(f.module != "intrusive" for f in result.findings)

    # The non-intrusive module still produced its finding.
    assert len(result.findings) == 1
    assert result.findings[0].module == "good"
    # No CRITICAL leaked in; highest is the HIGH from GoodModule.
    assert result.highest is Severity.HIGH


async def test_intrusive_module_runs_when_not_passive() -> None:
    engine = ScanEngine(make_scope(), make_config(passive=False), [GoodModule(), IntrusiveModule()])
    result = await engine.run()

    assert set(result.modules_run) == {"good", "intrusive"}
    modules_present = {f.module for f in result.findings}
    assert modules_present == {"good", "intrusive"}

    # The intrusive CRITICAL is now the most severe; exit code follows it.
    assert result.highest is Severity.CRITICAL
    assert result.exit_code() == EXIT_CODES[Severity.CRITICAL] == 40


# --------------------------------------------------------------------------------------
# Severity ordering: highest first.
# --------------------------------------------------------------------------------------

async def test_findings_sorted_by_descending_severity() -> None:
    # Pass modules in an order that is NOT already severity-sorted.
    engine = ScanEngine(
        make_scope(),
        make_config(passive=False),
        [LowModule(), GoodModule(), IntrusiveModule()],
    )
    result = await engine.run()

    severities = [f.severity for f in result.findings]
    assert severities == [Severity.CRITICAL, Severity.HIGH, Severity.LOW]
    # And it is genuinely sorted descending (not just coincidentally this list).
    assert severities == sorted(severities, reverse=True)
    assert result.exit_code() == EXIT_CODES[Severity.CRITICAL]


# --------------------------------------------------------------------------------------
# select_modules: filter by name and by passive flag.
# --------------------------------------------------------------------------------------

def test_select_modules_filters_by_name() -> None:
    engine = ScanEngine(
        make_scope(), make_config(), [GoodModule(), LowModule(), IntrusiveModule()]
    )

    # No filter -> all three (sorted by (order, name)).
    assert {m.name for m in engine.select_modules()} == {"good", "low", "intrusive"}

    # Explicit selection narrows to the requested names (case-insensitive).
    selected = engine.select_modules(["GOOD", "low"])
    assert {m.name for m in selected} == {"good", "low"}

    # Unknown names are ignored, not fatal.
    selected = engine.select_modules(["good", "does-not-exist"])
    assert {m.name for m in selected} == {"good"}


def test_select_modules_filters_intrusive_in_passive() -> None:
    modules = [GoodModule(), IntrusiveModule()]

    passive_engine = ScanEngine(make_scope(), make_config(passive=True), modules)
    assert {m.name for m in passive_engine.select_modules()} == {"good"}

    active_engine = ScanEngine(make_scope(), make_config(passive=False), modules)
    assert {m.name for m in active_engine.select_modules()} == {"good", "intrusive"}

    # Passive + explicit selection still drops the intrusive one.
    assert {m.name for m in passive_engine.select_modules(["good", "intrusive"])} == {"good"}


# --------------------------------------------------------------------------------------
# Empty result: no modules / no targets.
# --------------------------------------------------------------------------------------

async def test_empty_result_when_no_modules() -> None:
    engine = ScanEngine(make_scope(), make_config(), [])
    result = await engine.run()

    assert result.findings == []
    assert result.errors == []
    assert result.modules_run == []
    # Targets still resolved even though nothing ran against them.
    assert result.targets_scanned == 1
    assert result.exit_code() == EXIT_CODES[Severity.INFO] == 0


async def test_empty_result_when_no_targets_in_scope() -> None:
    # In scope: only 10.0.0.5; we ask modules to run but the engine resolves one
    # target. To get *zero* matching targets we exclude the only include.
    scope = Scope.from_dict(
        {
            "authorization": {"authorized": True, "authorized_by": "Test Harness"},
            "scope": {"targets": ["10.0.0.5"], "exclude": ["10.0.0.5"]},
        }
    )
    engine = ScanEngine(scope, make_config(), [GoodModule()])
    result = await engine.run()

    # The single include resolves to a target, but it is excluded from scope, so the
    # engine runs no (module, target) pairs and emits no findings.
    assert result.findings == []
    assert result.errors == []
    assert all(not scope.is_in_scope(t.host) for t in scope.targets())
    assert result.exit_code() == EXIT_CODES[Severity.INFO] == 0
