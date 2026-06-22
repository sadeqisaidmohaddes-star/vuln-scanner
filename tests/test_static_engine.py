"""Tests for the static-scan engine: discovery, module isolation, and repo prep."""
from __future__ import annotations

from pathlib import Path

import pytest

from vulnscan.core.models import Finding, Severity
from vulnscan.static.context import RepoContext, RepoMeta, StaticConfig
from vulnscan.static.engine import StaticEngine, discover_static_modules
from vulnscan.static.module_base import StaticModule
from vulnscan.static.repo import prepare_repo


def _repo(tmp_path: Path) -> RepoContext:
    return RepoContext(
        tmp_path,
        RepoMeta(source=str(tmp_path), label="t/repo"),
        StaticConfig(offline=True),
        http_client=None,
    )


def test_discovers_four_builtin_modules() -> None:
    names = {m.name for m in discover_static_modules()}
    assert {"secrets", "dependencies", "sensitive_files", "code_patterns"} <= names


class _GoodModule(StaticModule):
    name = "good_static"
    description = "returns one finding"
    default_severity = Severity.HIGH

    async def run(self, repo):
        return [
            self.finding(
                title="A static finding",
                severity=Severity.HIGH,
                description="d",
                target=repo.meta.label,
            )
        ]


class _DupModule(_GoodModule):
    name = "dup_static"  # same target+title as good -> different module, distinct key


class _BoomModule(StaticModule):
    name = "boom_static"
    description = "raises"

    async def run(self, repo):
        raise RuntimeError("kaboom")


async def test_module_isolation_and_result_shape(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    engine = StaticEngine(StaticConfig(offline=True), [_GoodModule(), _BoomModule()])
    result = await engine.run(repo)

    # The good module's finding survives; the boom module is isolated into errors.
    assert any(f.title == "A static finding" for f in result.findings)
    assert any(e["module"] == "boom_static" for e in result.errors)
    assert result.modules_run == ["good_static", "boom_static"] or set(result.modules_run) == {
        "good_static",
        "boom_static",
    }
    assert result.scope_summary.get("repository", {}).get("label") == "t/repo"
    assert result.highest is Severity.HIGH


async def test_deduplication(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    # Two instances of the same module produce the same (module,target,title) -> one finding.
    engine = StaticEngine(StaticConfig(offline=True), [_GoodModule(), _GoodModule()])
    result = await engine.run(repo)
    assert len([f for f in result.findings if f.title == "A static finding"]) == 1


async def test_module_selection_by_name(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    engine = StaticEngine(StaticConfig(offline=True), [_GoodModule(), _BoomModule()])
    result = await engine.run(repo, ["good_static"])
    assert result.modules_run == ["good_static"]
    assert not result.errors  # boom was not selected


async def test_prepare_repo_local_dir(tmp_path: Path) -> None:
    (tmp_path / "file.txt").write_text("hello", encoding="utf-8")
    repo = await prepare_repo(str(tmp_path))
    try:
        assert repo.meta.is_remote is False
        assert repo.root.resolve() == tmp_path.resolve()
    finally:
        repo.cleanup()  # no-op for local dirs
    # cleanup must not delete a local (non-cloned) directory
    assert tmp_path.exists()
