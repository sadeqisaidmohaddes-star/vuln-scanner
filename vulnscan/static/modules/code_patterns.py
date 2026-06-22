"""Lightweight insecure-code pattern scanner (a heuristic SAST pass).

This module loads a bundle of regex-based "insecure code" rules from
``code_patterns.json`` and matches them, line by line, against the repository's
text files. It is a linter, not a prover: rules are heuristics and many default
to ``"tentative"`` confidence because false positives are expected.

The scan is strictly read-only — files are read but never executed — and it is
designed to degrade quietly: a malformed rule, an unparsable data file, or an
unreadable source file is skipped rather than raised.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional, Pattern

from ..module_base import StaticModule
from ...core.datafiles import load_json
from ...core.models import Finding, Severity

if TYPE_CHECKING:
    from ..context import RepoContext


# Maximum findings emitted for any single (file, rule) pair, to avoid a pattern
# that matches on every line from flooding the report.
_MAX_PER_FILE_RULE: int = 25

# Lines longer than this almost certainly come from a minified or bundled asset;
# scanning them is pointless and slow, so they are skipped.
_MINIFIED_LINE_LEN: int = 2000

# Snippet evidence is trimmed to this length so we report a locating excerpt, not
# whole file contents.
_SNIPPET_MAX_LEN: int = 160


class _CompiledRule:
    """A single pre-compiled insecure-code rule.

    Wraps the raw JSON rule dict together with its compiled regex so each source
    line is matched against ready-to-use :class:`re.Pattern` objects rather than
    recompiling per file.
    """

    __slots__ = (
        "id",
        "name",
        "regex",
        "severity",
        "cwe",
        "confidence",
        "description",
        "remediation",
    )

    def __init__(self, rule: dict[str, Any], pattern: "Pattern[str]") -> None:
        self.id: str = str(rule.get("id", ""))
        self.name: str = str(rule.get("name") or rule.get("id") or "Insecure code pattern")
        self.regex: "Pattern[str]" = pattern
        self.severity: Severity = self._parse_severity(rule.get("severity"))
        self.cwe: str = str(rule.get("cwe") or "")
        self.confidence: str = str(rule.get("confidence") or "tentative")
        self.description: str = str(rule.get("description") or "")
        self.remediation: str = str(rule.get("remediation") or "")

    @staticmethod
    def _parse_severity(value: Any) -> Severity:
        """Parse a severity string into a :class:`Severity`, defaulting to MEDIUM."""
        if isinstance(value, Severity):
            return value
        try:
            return Severity.from_str(str(value))
        except (ValueError, AttributeError):
            return Severity.MEDIUM


class CodePatternsModule(StaticModule):
    """Match regex-based insecure-code rules against repository text files."""

    name = "code_patterns"
    description = "Lightweight regex scan for insecure code patterns (heuristic SAST)."
    category = "sast"
    default_severity = Severity.MEDIUM
    order = 40

    def __init__(self) -> None:
        """Load and pre-compile the rule set, indexed by file suffix."""
        # Maps a lowercased file suffix (e.g. ".py") -> list of rules that apply.
        self._by_suffix: dict[str, list[_CompiledRule]] = {}
        self._load_rules()

    # -- rule loading ----------------------------------------------------------------

    def _load_rules(self) -> None:
        """Load ``code_patterns.json`` and build the suffix -> rules index.

        Bad regexes are skipped individually; a missing or unparsable data file
        leaves the index empty (the module then simply produces no findings).
        """
        try:
            data = load_json("code_patterns.json")
        except (OSError, ValueError):
            return

        patterns = data.get("patterns") if isinstance(data, dict) else None
        if not isinstance(patterns, list):
            return

        for raw in patterns:
            if not isinstance(raw, dict):
                continue
            regex_src = raw.get("regex")
            suffixes = raw.get("suffixes")
            if not isinstance(regex_src, str) or not isinstance(suffixes, list):
                continue
            try:
                compiled = re.compile(regex_src)
            except re.error:
                # Skip a malformed regex rather than aborting the whole rule set.
                continue
            rule = _CompiledRule(raw, compiled)
            for suffix in suffixes:
                if not isinstance(suffix, str) or not suffix:
                    continue
                self._by_suffix.setdefault(suffix.lower(), []).append(rule)

    # -- module API ------------------------------------------------------------------

    def applicable(self, repo: "RepoContext") -> bool:
        """Always applicable: the pattern scan runs against every repository."""
        return True

    async def run(self, repo: "RepoContext") -> list[Finding]:
        """Scan every text file against its suffix-applicable rules.

        For each readable file we look up the rules that target its suffix and
        match each rule against the file line by line, emitting a finding per
        match (capped per file/rule). Minified-looking lines and binary/oversize
        files are skipped. This method never raises on expected I/O conditions.
        """
        findings: list[Finding] = []

        if not self._by_suffix:
            return findings

        # Only iterate files whose suffix has at least one applicable rule.
        suffixes = set(self._by_suffix.keys())

        for path in repo.iter_files(suffixes=suffixes):
            try:
                rules = self._by_suffix.get(Path(path).suffix.lower())
                if not rules:
                    continue
                text = repo.read_text(path)
                if text is None:
                    continue
                findings.extend(self._scan_file(repo, path, text, rules))
            except Exception as exc:  # pragma: no cover - defensive: never abort the scan
                repo.log.debug("code_patterns: skipping %s: %s", repo.rel(path), exc)
                continue

        return findings

    # -- scanning helpers ------------------------------------------------------------

    def _scan_file(
        self,
        repo: "RepoContext",
        path: Path,
        text: str,
        rules: list[_CompiledRule],
    ) -> list[Finding]:
        """Match every applicable rule against ``text`` line by line.

        Returns the findings for this single file. Per (file, rule) emission is
        capped at :data:`_MAX_PER_FILE_RULE`.
        """
        findings: list[Finding] = []
        rel = repo.rel(path)
        # Tracks how many findings each rule has produced for THIS file.
        counts: dict[str, int] = {}

        lines = text.split("\n")
        for lineno, line in enumerate(lines, start=1):
            # Skip minified/bundled lines: they are unreadable and pattern-noisy.
            if len(line) > _MINIFIED_LINE_LEN:
                continue
            for rule in rules:
                if counts.get(rule.id, 0) >= _MAX_PER_FILE_RULE:
                    continue
                if rule.regex.search(line) is None:
                    continue
                counts[rule.id] = counts.get(rule.id, 0) + 1
                findings.append(
                    self._build_finding(repo, path, rel, lineno, line, rule)
                )

        return findings

    def _build_finding(
        self,
        repo: "RepoContext",
        path: Path,
        rel: str,
        lineno: int,
        line: str,
        rule: _CompiledRule,
    ) -> Finding:
        """Construct a :class:`Finding` for one rule match on ``line``."""
        snippet = self._trim_snippet(line)
        references: list[str] = [rule.cwe] if rule.cwe else []
        return self.finding(
            title=rule.name,
            severity=rule.severity,
            description=rule.description,
            target=repo.finding_target(path, lineno),
            evidence={
                "file": rel,
                "line": lineno,
                "rule": rule.id,
                "snippet": snippet,
            },
            remediation=rule.remediation,
            references=references,
            confidence=rule.confidence,
        )

    @staticmethod
    def _trim_snippet(line: str) -> str:
        """Strip surrounding whitespace and clamp to :data:`_SNIPPET_MAX_LEN` chars."""
        snippet = line.strip()
        if len(snippet) > _SNIPPET_MAX_LEN:
            snippet = snippet[:_SNIPPET_MAX_LEN]
        return snippet


# Optional alias kept descriptive; the engine discovers by StaticModule subclass.
__all__ = ["CodePatternsModule"]
