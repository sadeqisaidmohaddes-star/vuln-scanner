"""Static module: hardcoded secret / credential detection.

Scans every readable text file in the working tree for known secret patterns
(API keys, tokens, private keys, hardcoded passwords, ...) loaded from the
bundled ``secret_patterns.json`` data file. Each pattern is a pre-compiled regex
applied with :meth:`re.Pattern.finditer`.

This module is DETECTION-AND-REPORTING ONLY and strictly READ-ONLY: it never
executes repository code, never modifies the tree, and never exfiltrates file
contents. The matched secret value is always REDACTED before it leaves this
module — only a redacted form (first 4 + last 2 chars, middle elided, or fully
masked when short) ever appears in a finding.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Pattern

from ..module_base import StaticModule
from ...core.datafiles import load_json
from ...core.models import Finding, Severity

if TYPE_CHECKING:
    from ..context import RepoContext


# Cap matches emitted per (file, rule) so a pathological file can't explode output.
_MAX_PER_FILE_RULE = 25

# Substrings (matched case-insensitively against the repo-relative path) that mark
# a file as a test/example/sample, which downgrades confidence to "tentative".
_TEST_PATH_MARKERS: tuple[str, ...] = (
    "test",
    "example",
    "sample",
    "fixture",
    "mock",
    "spec",
)


def _redact(value: str) -> str:
    """Return a redacted form of ``value`` safe to embed in a finding.

    Shows the first 4 and last 2 characters with the middle replaced by a single
    ``…`` ellipsis. Values shorter than 8 characters are fully masked (no plaintext
    fragment survives), so the raw secret is never reproduced in full.
    """
    if len(value) < 8:
        return "*" * len(value)
    return f"{value[:4]}…{value[-2:]}"


class SecretsModule(StaticModule):
    """Detect hardcoded secrets and credentials embedded in source files."""

    name = "secrets"
    description = "Detects hardcoded secrets and credentials in source files."
    category = "secrets"
    default_severity = Severity.HIGH
    order = 20

    def applicable(self, repo: "RepoContext") -> bool:
        """Secret scanning is always relevant to any repository."""
        return True

    def _load_patterns(self, repo: "RepoContext") -> list[dict]:
        """Load and pre-compile secret patterns from ``secret_patterns.json``.

        Returns a list of pattern dicts each augmented with a compiled ``_regex``
        :class:`re.Pattern`. A pattern with a missing or uncompilable regex is
        skipped. Any failure loading the data file degrades to an empty list
        rather than raising.
        """
        try:
            raw = load_json("secret_patterns.json")
        except Exception as exc:  # noqa: BLE001 - degrade on any load/parse error
            repo.log.warning("secrets: could not load secret_patterns.json: %s", exc)
            return []

        patterns_in = raw.get("patterns") if isinstance(raw, dict) else None
        if not isinstance(patterns_in, list):
            return []

        compiled: list[dict] = []
        for entry in patterns_in:
            if not isinstance(entry, dict):
                continue
            regex = entry.get("regex")
            if not isinstance(regex, str) or not regex:
                continue
            try:
                pattern: Pattern[str] = re.compile(regex)
            except re.error as exc:
                repo.log.debug(
                    "secrets: skipping bad regex for rule %r: %s",
                    entry.get("id"),
                    exc,
                )
                continue
            merged = dict(entry)
            merged["_regex"] = pattern
            compiled.append(merged)
        return compiled

    async def run(self, repo: "RepoContext") -> list[Finding]:
        """Scan every text file for compiled secret patterns and emit findings."""
        findings: list[Finding] = []
        patterns = self._load_patterns(repo)
        if not patterns:
            return findings

        remediation = (
            "Remove the secret from source, rotate/revoke it immediately, and "
            "purge it from git history (it remains in history even after "
            "deletion). Load secrets from environment variables or a secrets "
            "manager."
        )

        for path in repo.iter_files():
            try:
                text = repo.read_text(path)
            except Exception:  # noqa: BLE001 - never raise on an unreadable file
                continue
            if text is None:
                continue

            rel = repo.rel(path)
            is_testish = any(marker in rel.lower() for marker in _TEST_PATH_MARKERS)

            for pattern in patterns:
                regex: Pattern[str] = pattern["_regex"]
                pattern_id = str(pattern.get("id", "unknown"))
                pattern_name = str(pattern.get("name", pattern_id))

                try:
                    severity = Severity.from_str(str(pattern.get("severity", "high")))
                except ValueError:
                    severity = self.default_severity

                base_confidence = str(pattern.get("confidence", "firm"))
                confidence = "tentative" if is_testish else base_confidence
                references = pattern.get("references", [])
                if not isinstance(references, list):
                    references = []

                emitted = 0
                try:
                    matches = regex.finditer(text)
                except Exception:  # noqa: BLE001 - defensive; bad input shouldn't crash
                    continue

                for match in matches:
                    if emitted >= _MAX_PER_FILE_RULE:
                        break
                    line = text.count("\n", 0, match.start()) + 1
                    redacted = _redact(match.group(0))
                    findings.append(
                        self.finding(
                            title=f"Hardcoded secret: {pattern_name}",
                            severity=severity,
                            description=(
                                f"A {pattern_name} credential/secret pattern was "
                                f"found hardcoded in source at {rel}:{line}. "
                                "Secrets committed to a repository are exposed to "
                                "anyone with read access and remain recoverable "
                                "from git history."
                            ),
                            target=repo.finding_target(path, line),
                            evidence={
                                "file": rel,
                                "line": line,
                                "rule": pattern_id,
                                "match": redacted,
                            },
                            remediation=remediation,
                            references=list(references),
                            confidence=confidence,
                        )
                    )
                    emitted += 1

        return findings
