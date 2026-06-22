"""Software Composition Analysis: find dependencies with known vulnerabilities.

Parses dependency manifests/lockfiles from the repository, then matches each
``(ecosystem, name, version)`` against known-vulnerability data:

* **Primary** — the live `OSV.dev <https://osv.dev>`_ database (free, no auth),
  queried in a single batch with per-vuln detail lookups.
* **Fallback** — a small bundled offline DB (``dependency_vulns.json``) used when
  offline or when the OSV query fails.

This module is read-only and never executes project code or installs anything.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Iterable, Optional

from ...core.datafiles import load_json
from ...core.models import Finding, Severity
from ...core.versioning import version_satisfies
from ..module_base import StaticModule

if TYPE_CHECKING:
    from ..context import RepoContext

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
MAX_DEPS = 500
MAX_DETAIL_LOOKUPS = 60

# OSV / GitHub severity words -> our Severity.
_WORD_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class Dependency:
    """One resolved dependency observed in a manifest."""

    __slots__ = ("ecosystem", "name", "version", "manifest")

    def __init__(self, ecosystem: str, name: str, version: str, manifest: str) -> None:
        self.ecosystem = ecosystem
        self.name = name
        self.version = version
        self.manifest = manifest

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.ecosystem.lower(), self.name.lower(), self.version)


class DependenciesModule(StaticModule):
    """Detect dependencies with known CVEs via OSV (with an offline fallback DB)."""

    name = "dependencies"
    description = "Match dependency versions against known vulnerabilities (OSV.dev + offline DB)."
    category = "dependency"
    default_severity = Severity.HIGH
    order = 30

    async def run(self, repo: "RepoContext") -> list[Finding]:
        deps = self._collect(repo)
        if not deps:
            return []

        findings: list[Finding] = []
        seen: set[tuple[str, str, str, str]] = set()  # (name, version, source, vuln-id)

        used_osv = False
        if repo.has_http:
            try:
                findings.extend(await self._match_osv(repo, deps, seen))
                used_osv = True
            except Exception as exc:  # noqa: BLE001 - any OSV failure -> offline fallback
                repo.log.debug("dependencies: OSV lookup failed, using offline DB: %s", exc)

        if not used_osv:
            findings.extend(self._match_offline(repo, deps, seen))
        return findings

    # -- manifest collection ---------------------------------------------------------

    def _collect(self, repo: "RepoContext") -> list[Dependency]:
        deps: dict[tuple[str, str, str], Dependency] = {}

        def add(eco: str, name: str, version: str, manifest: str) -> None:
            name = (name or "").strip()
            version = (version or "").strip().lstrip("=")
            if not name or not version or len(deps) >= MAX_DEPS:
                return
            dep = Dependency(eco, name, version, manifest)
            deps.setdefault(dep.key, dep)

        for path in repo.iter_files(
            names={
                "requirements.txt", "requirements-dev.txt", "Pipfile.lock", "poetry.lock",
                "package.json", "package-lock.json", "pom.xml", "go.mod",
            },
            suffixes={".txt"},
        ):
            fname = path.name.lower()
            rel = repo.rel(path)
            text = repo.read_text(path)
            if text is None:
                continue
            try:
                if fname.startswith("requirements") and fname.endswith(".txt"):
                    for n, v in self._parse_requirements(text):
                        add("PyPI", n, v, rel)
                elif fname == "pipfile.lock":
                    for n, v in self._parse_pipfile_lock(text):
                        add("PyPI", n, v, rel)
                elif fname == "poetry.lock":
                    for n, v in self._parse_poetry_lock(text):
                        add("PyPI", n, v, rel)
                elif fname == "package-lock.json":
                    for n, v in self._parse_package_lock(text):
                        add("npm", n, v, rel)
                elif fname == "package.json":
                    for n, v in self._parse_package_json(text):
                        add("npm", n, v, rel)
                elif fname == "pom.xml":
                    for n, v in self._parse_pom(text):
                        add("Maven", n, v, rel)
                elif fname == "go.mod":
                    for n, v in self._parse_go_mod(text):
                        add("Go", n, v, rel)
            except Exception as exc:  # noqa: BLE001 - a bad manifest must not break the scan
                repo.log.debug("dependencies: failed parsing %s: %s", rel, exc)
        return list(deps.values())

    @staticmethod
    def _parse_requirements(text: str) -> Iterable[tuple[str, str]]:
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]+\])?\s*===?\s*([A-Za-z0-9_.\-+!]+)", line)
            if m:
                yield m.group(1), m.group(2)

    @staticmethod
    def _parse_pipfile_lock(text: str) -> Iterable[tuple[str, str]]:
        data = json.loads(text)
        for section in ("default", "develop"):
            for name, spec in (data.get(section) or {}).items():
                ver = (spec or {}).get("version", "") if isinstance(spec, dict) else ""
                if ver:
                    yield name, ver.lstrip("=")

    @staticmethod
    def _parse_poetry_lock(text: str) -> Iterable[tuple[str, str]]:
        name: Optional[str] = None
        for line in text.splitlines():
            s = line.strip()
            if s == "[[package]]":
                name = None
            elif s.startswith("name = "):
                name = s.split("=", 1)[1].strip().strip('"')
            elif s.startswith("version = ") and name:
                yield name, s.split("=", 1)[1].strip().strip('"')
                name = None

    @staticmethod
    def _parse_package_json(text: str) -> Iterable[tuple[str, str]]:
        data = json.loads(text)
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            for name, spec in (data.get(section) or {}).items():
                ver = DependenciesModule._clean_npm_version(str(spec))
                if ver:
                    yield name, ver

    @staticmethod
    def _parse_package_lock(text: str) -> Iterable[tuple[str, str]]:
        data = json.loads(text)
        # npm v7+ ("packages") and v6 ("dependencies").
        for key, spec in (data.get("packages") or {}).items():
            if not key or not isinstance(spec, dict):
                continue
            name = key.split("node_modules/")[-1]
            ver = spec.get("version")
            if name and ver:
                yield name, ver
        for name, spec in (data.get("dependencies") or {}).items():
            if isinstance(spec, dict) and spec.get("version"):
                yield name, spec["version"]

    @staticmethod
    def _parse_pom(text: str) -> Iterable[tuple[str, str]]:
        for block in re.findall(r"<dependency>(.*?)</dependency>", text, re.DOTALL | re.IGNORECASE):
            aid = re.search(r"<artifactId>\s*([^<]+?)\s*</artifactId>", block, re.IGNORECASE)
            ver = re.search(r"<version>\s*([^<]+?)\s*</version>", block, re.IGNORECASE)
            if aid and ver and "${" not in ver.group(1):
                yield aid.group(1).strip(), ver.group(1).strip()

    @staticmethod
    def _parse_go_mod(text: str) -> Iterable[tuple[str, str]]:
        for m in re.finditer(r"^\s*(?:require\s+)?([\w./\-]+)\s+v([0-9][\w.\-+]*)", text, re.MULTILINE):
            mod = m.group(1)
            if mod in ("require", "module", "go", "toolchain"):
                continue
            yield mod, m.group(2)

    @staticmethod
    def _clean_npm_version(spec: str) -> Optional[str]:
        spec = spec.strip()
        if any(spec.startswith(p) for p in ("workspace:", "file:", "link:", "git+", "github:", "npm:")):
            return None
        if spec in ("*", "latest", "") or "||" in spec or " - " in spec:
            return None
        m = re.search(r"(\d+\.\d+(?:\.\d+)?(?:[-+][\w.]+)?)", spec)
        return m.group(1) if m else None

    # -- matching: OSV ---------------------------------------------------------------

    async def _match_osv(
        self,
        repo: "RepoContext",
        deps: list[Dependency],
        seen: set,
    ) -> list[Finding]:
        import httpx

        queries = [
            {"version": d.version, "package": {"name": d.name,
             "ecosystem": "Go" if d.ecosystem == "Go" else d.ecosystem}}
            for d in deps
        ]
        resp = await repo.http.post(OSV_BATCH_URL, json={"queries": queries},
                                    timeout=repo.config.timeout)
        resp.raise_for_status()
        results = resp.json().get("results", [])

        # Map dep -> list of vuln ids; gather unique ids for detail lookups.
        dep_vulns: list[tuple[Dependency, list[str]]] = []
        unique_ids: list[str] = []
        for dep, result in zip(deps, results):
            ids = [v.get("id") for v in (result or {}).get("vulns", []) if v.get("id")]
            if ids:
                dep_vulns.append((dep, ids))
                for vid in ids:
                    if vid not in unique_ids:
                        unique_ids.append(vid)

        details: dict[str, dict] = {}
        for vid in unique_ids[:MAX_DETAIL_LOOKUPS]:
            try:
                d = await repo.http.get(OSV_VULN_URL + vid, timeout=repo.config.timeout)
                if d.status_code == 200:
                    details[vid] = d.json()
            except Exception as exc:  # noqa: BLE001
                repo.log.debug("dependencies: OSV detail fetch failed for %s: %s", vid, exc)

        findings: list[Finding] = []
        for dep, ids in dep_vulns:
            for vid in ids:
                key = (dep.name.lower(), dep.version, "osv", vid)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(self._finding_from_osv(repo, dep, vid, details.get(vid, {})))
        return findings

    def _finding_from_osv(self, repo: "RepoContext", dep: Dependency, vid: str, detail: dict) -> Finding:
        summary = detail.get("summary") or detail.get("details", "")[:160] or vid
        aliases = [a for a in detail.get("aliases", []) if isinstance(a, str)]
        severity = self._osv_severity(detail)
        refs = [a for a in aliases if a.startswith(("CVE-", "GHSA-"))]
        refs.append(f"https://osv.dev/vulnerability/{vid}")
        refs = list(dict.fromkeys(refs))
        return self.finding(
            title=f"{dep.name} {dep.version}: {summary}".strip(),
            severity=severity,
            description=(detail.get("details") or summary or
                        f"{dep.name} {dep.version} is affected by {vid}.")[:600],
            target=repo.finding_target(Path(dep.manifest)),
            evidence={
                "ecosystem": dep.ecosystem, "package": dep.name, "version": dep.version,
                "manifest": dep.manifest, "source": "osv", "vuln_id": vid,
            },
            remediation=f"Upgrade {dep.name} to a non-vulnerable release (see the advisory).",
            references=refs,
            confidence="firm",
        )

    @staticmethod
    def _osv_severity(detail: dict) -> Severity:
        word = (detail.get("database_specific") or {}).get("severity")
        if isinstance(word, str) and word.upper() in _WORD_SEVERITY:
            return _WORD_SEVERITY[word.upper()]
        # Some ecosystems put severity on affected[].database_specific.
        for aff in detail.get("affected", []):
            w = (aff.get("database_specific") or {}).get("severity")
            if isinstance(w, str) and w.upper() in _WORD_SEVERITY:
                return _WORD_SEVERITY[w.upper()]
        return Severity.HIGH

    # -- matching: offline DB --------------------------------------------------------

    def _match_offline(self, repo: "RepoContext", deps: list[Dependency], seen: set) -> list[Finding]:
        try:
            advisories = load_json("dependency_vulns.json").get("advisories", [])
        except Exception as exc:  # noqa: BLE001
            repo.log.debug("dependencies: could not load offline DB: %s", exc)
            return []

        findings: list[Finding] = []
        for dep in deps:
            for adv in advisories:
                if str(adv.get("ecosystem", "")).lower() != dep.ecosystem.lower():
                    continue
                if str(adv.get("package", "")).lower() != dep.name.lower():
                    continue
                if not version_satisfies(dep.version, adv.get("affected", {})):
                    continue
                cve = adv.get("cve", "")
                key = (dep.name.lower(), dep.version, "local", cve or adv.get("title", ""))
                if key in seen:
                    continue
                seen.add(key)
                refs = []
                if cve:
                    refs.append(cve)
                if adv.get("cwe"):
                    refs.append(adv["cwe"])
                refs.extend(adv.get("references", []))
                refs = list(dict.fromkeys(refs))
                findings.append(self.finding(
                    title=f"{dep.name} {dep.version}: {adv.get('title', cve)}",
                    severity=Severity.from_str(adv.get("severity", "High")),
                    description=adv.get("title", "") +
                                (f" Fixed in {adv['fixed']}." if adv.get("fixed") else ""),
                    target=repo.finding_target(Path(dep.manifest)),
                    evidence={
                        "ecosystem": dep.ecosystem, "package": dep.name, "version": dep.version,
                        "manifest": dep.manifest, "source": "local-db", "cve": cve,
                    },
                    remediation=f"Upgrade {dep.name}" + (f" to {adv['fixed']} or later." if adv.get("fixed") else "."),
                    references=refs,
                    confidence="firm",
                ))
        return findings
