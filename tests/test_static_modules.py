"""Offline tests for the built-in static (source-repository) scanner modules.

Each test builds a tiny repository in ``tmp_path``, wraps it in a
:class:`~vulnscan.static.context.RepoContext` configured for ``offline`` operation
(``http_client=None``), and runs a single module's ``run`` coroutine directly via
``await``. No network, git clone, or live feed is touched: dependency lookups fall
back to the bundled ``dependency_vulns.json`` database.

The four modules covered are ``secrets``, ``dependencies``, ``sensitive_files``,
and ``code_patterns``. The dependencies module talks to OSV.dev when online and
falls back to the bundled DB offline; if that module is not present in this build
its test self-skips rather than failing the suite.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import pytest

from vulnscan.core.models import Finding, Severity
from vulnscan.static.context import RepoContext, RepoMeta, StaticConfig
from vulnscan.static.engine import discover_static_modules
from vulnscan.static.modules.code_patterns import CodePatternsModule
from vulnscan.static.modules.secrets import SecretsModule
from vulnscan.static.modules.sensitive_files import SensitiveFilesModule


# The raw AWS access-key id we plant. It is assembled from fragments so the
# literal 20-char secret never appears as a single token in *this* source file --
# only in the temp repo we build and (redacted) in the finding under test.
_AKIA_PREFIX = "AKIA"
_AKIA_BODY = "IOSFODNN7" + "EXAMPLE"  # 16 chars -> AKIA + 16 = 20-char access key id
_RAW_AWS_KEY = _AKIA_PREFIX + _AKIA_BODY  # "AKIAIOSFODNN7EXAMPLE"


def _make_repo(root: Path, *, label: str = "demo") -> RepoContext:
    """Wrap a local directory as an OFFLINE RepoContext (no HTTP client)."""
    meta = RepoMeta(source=str(root), label=label, is_remote=False, name=label)
    config = StaticConfig(offline=True)
    return RepoContext(root, meta, config, http_client=None)


def _texts(findings: list[Finding]) -> str:
    """All searchable text across a list of findings (titles, evidence, refs)."""
    chunks: list[str] = []
    for f in findings:
        chunks.append(f.title)
        chunks.append(f.description)
        chunks.append(repr(f.evidence))
        chunks.extend(str(r) for r in f.references)
    return "\n".join(chunks)


# --------------------------------------------------------------------------- #
# secrets                                                                      #
# --------------------------------------------------------------------------- #


async def test_secrets_detects_aws_key_and_redacts_it(tmp_path: Path) -> None:
    """An AKIA... access key id is found, and the raw secret is never leaked."""
    # The file itself assembles the key from string fragments, but the resulting
    # source text contains the full 20-char "AKIAIOSFODNN7EXAMPLE" token, which the
    # bundled aws-access-key-id pattern matches via \b(?:AKIA|...)[0-9A-Z]{16}\b.
    config_py = tmp_path / "config.py"
    config_py.write_text(
        'AWS_KEY = "' + _AKIA_PREFIX + '" + "' + _AKIA_BODY + '"\n'
        # Also include a flat occurrence so the regex matches the full token.
        'AWS_KEY_FLAT = "' + _RAW_AWS_KEY + '"\n',
        encoding="utf-8",
    )

    repo = _make_repo(tmp_path)
    findings = await SecretsModule().run(repo)

    aws = [f for f in findings if "AWS Access Key ID" in f.title]
    assert aws, f"expected an AWS access-key finding, got titles={[f.title for f in findings]}"

    finding = aws[0]
    assert finding.severity == Severity.HIGH
    assert finding.module == "secrets"
    assert "CWE-798" in finding.references

    # The redacted form keeps only the first 4 + last 2 chars: "AKIA…LE".
    assert finding.evidence.get("match") == "AKIA…LE"

    # The raw secret must NOT survive anywhere user-visible in the finding.
    assert _RAW_AWS_KEY not in finding.title
    assert _RAW_AWS_KEY not in repr(finding.evidence)
    assert _RAW_AWS_KEY not in _texts([finding])


# --------------------------------------------------------------------------- #
# dependencies                                                                 #
# --------------------------------------------------------------------------- #


def _dependencies_module():
    """Return the discovered dependencies static module, or None if absent."""
    for mod in discover_static_modules():
        if mod.name in ("dependencies", "dependency", "deps"):
            return mod
    return None


async def test_dependencies_offline_matches_bundled_cve(tmp_path: Path) -> None:
    """requests==2.19.0 matches CVE-2018-18074 (requests<2.20.0) from the bundled DB."""
    module = _dependencies_module()
    if module is None:
        pytest.skip("dependencies static module is not present in this build")

    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n", encoding="utf-8")

    repo = _make_repo(tmp_path)
    # Offline mode: no HTTP client, so the module must fall back to the bundled
    # dependency_vulns.json rather than querying OSV.dev.
    assert repo.has_http is False
    findings = await module.run(repo)

    refs_blob = _texts(findings)
    assert "CVE-2018-18074" in refs_blob, (
        "expected the requests<2.20.0 advisory CVE-2018-18074 to be referenced; "
        f"got {[(f.title, f.references) for f in findings]}"
    )


# --------------------------------------------------------------------------- #
# sensitive_files                                                              #
# --------------------------------------------------------------------------- #


async def test_sensitive_files_env_vs_env_example(tmp_path: Path) -> None:
    """A real .env is a HIGH 'Sensitive file committed' finding; .env.example is INFO."""
    (tmp_path / ".env").write_text("DB_PASSWORD=hunter2\n", encoding="utf-8")
    (tmp_path / ".env.example").write_text("DB_PASSWORD=changeme\n", encoding="utf-8")

    repo = _make_repo(tmp_path)
    findings = await SensitiveFilesModule().run(repo)

    by_file: dict[str, Finding] = {}
    for f in findings:
        # evidence["file"] is the repo-relative path (".env", ".env.example").
        by_file[str(f.evidence.get("file"))] = f

    assert ".env" in by_file, f"expected a finding for .env; got {list(by_file)}"
    assert ".env.example" in by_file, f"expected a finding for .env.example; got {list(by_file)}"

    env_finding = by_file[".env"]
    example_finding = by_file[".env.example"]

    # Both are titled "Sensitive file committed: <path>".
    assert env_finding.title.startswith("Sensitive file committed")
    assert example_finding.title.startswith("Sensitive file committed")

    # The real env file is treated as a genuine secret exposure (HIGH); the
    # example/template is a mere hygiene note (INFO) -- strictly lower severity.
    assert env_finding.severity == Severity.HIGH
    assert example_finding.severity == Severity.INFO
    assert example_finding.severity < env_finding.severity
    assert env_finding.evidence.get("category") == "env_file"
    assert example_finding.evidence.get("category") == "env_example"
    assert example_finding.evidence.get("is_example") is True


# --------------------------------------------------------------------------- #
# code_patterns                                                                #
# --------------------------------------------------------------------------- #


async def test_code_patterns_flags_shell_true(tmp_path: Path) -> None:
    """subprocess.run(cmd, shell=True) trips the py-shell-true rule (CWE-78)."""
    (tmp_path / "danger.py").write_text(
        "import subprocess\n"
        "def run(cmd):\n"
        "    return subprocess.run(cmd, shell=True)\n",
        encoding="utf-8",
    )

    repo = _make_repo(tmp_path)
    findings = await CodePatternsModule().run(repo)

    shell_findings = [
        f
        for f in findings
        if "CWE-78" in f.references and "shell" in f.title.lower()
    ]
    assert shell_findings, (
        "expected a shell=True (CWE-78) finding; got "
        f"{[(f.title, f.references) for f in findings]}"
    )

    finding = shell_findings[0]
    assert finding.severity == Severity.HIGH
    assert finding.module == "code_patterns"
    assert finding.evidence.get("rule") == "py-shell-true"
    assert "shell=True" in str(finding.evidence.get("snippet", ""))
    assert str(finding.evidence.get("file")) == "danger.py"
