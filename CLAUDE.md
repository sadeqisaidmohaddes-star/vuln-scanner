# CLAUDE.md

Guidance for working in this repository (read this before making changes).

`vulnscan` is a **modular, async vulnerability scanner for *authorized* security
assessments**. It is strictly **detection-and-reporting**: it identifies
misconfigurations, exposures, and known-vulnerable software and produces reports.
It never exploits, exfiltrates, brute-forces, or performs destructive actions.

It has three cooperating parts that share one data model:

1. **Live (network) scanner** — probes a running target (ports, TLS, HTTP, DNS,
   exposed files, injection signals, default creds, CVE correlation).
2. **Static (repository) scanner** — reads a cloned repo's source (secrets,
   vulnerable dependencies, sensitive committed files, risky code patterns).
3. **Web dashboard** — a local FastAPI app that drives both from the browser.

---

## Goals

- **Safety first.** Every capability is detection-only and gated behind explicit
  authorization. The tool should be impossible to *accidentally* point at a
  third party, and should never run target/repo code.
- **Modular & extensible.** New checks are drop-in modules discovered at runtime;
  adding one should not require touching the engine.
- **Correlated, actionable findings.** Structured findings with severity,
  evidence, remediation, and CVE/CWE references — not raw tool output.
- **Usable everywhere.** Clean CLI for engagements/CI, plus a polished local web
  dashboard for interactive use. Console, JSON, and HTML reporting.
- **Quality.** Type hints + docstrings throughout, graceful per-module error
  isolation (one failing module never aborts a scan), and a real test suite.

---

## Golden rules (do not violate)

These are the project's reason for existing — preserve them in every change:

1. **Authorization gate is mandatory for live scans.** A network scan is refused
   unless the operator confirms authorization (`--authorize` on the CLI, the
   `authorized` attestation in the web API) **and**, for scope-file mode,
   `authorization.authorized: true` with a non-empty `authorized_by` (with
   `expires` enforced). The single chokepoint is
   `vulnscan/core/authorization.py::Authorization.require`.
2. **Scope is enforced before every probe.** The engine checks
   `Scope.is_in_scope(host)` before any module touches a target; `exclude` always
   wins. Never add a code path that reaches a host without this check.
3. **Detection only — never exploit or exfiltrate.**
   - `exposed_files` reports *reachability* (status/length/type); it must never
     download or store response bodies.
   - `injection_detect` uses benign reflection / single-quote *signals* only — no
     data extraction, no destructive/stacked/time-based payloads.
   - `default_creds` makes at most one attempt per credential and stops on success
     (no post-auth actions).
   - `secrets` reports matches **redacted** — the secret value is never emitted.
4. **The static scanner never executes repository code.** Repos are shallow-cloned
   to a temp dir and only *read*. No build, install, or run steps — ever.
5. **Modules must degrade gracefully.** Catch expected failures (timeouts,
   refused connections, TLS/DNS errors, unparsable files) and return partial/empty
   results. The engine isolates unexpected exceptions into `result.errors`, but
   well-behaved modules handle their own expected errors.

---

## Architecture

```
                         ┌────────────────────────┐
                         │   vulnscan.core         │  shared contract
                         │  models · scope · auth  │  (Finding, Severity,
                         │  ratelimit · aggregate  │   Target, ScanResult)
                         └───────────┬────────────┘
              ┌────────────────────── ┼ ───────────────────────┐
   ┌──────────▼───────────┐   ┌──────▼────────────┐   ┌─────────▼──────────┐
   │ Live engine          │   │ Static engine      │   │ Reporting          │
   │ core/engine.py       │   │ static/engine.py   │   │ console·json·html  │
   │ ScannerModule (net)  │   │ StaticModule (repo)│   └────────────────────┘
   │ → ScanContext        │   │ → RepoContext      │
   └──────────┬───────────┘   └──────┬─────────────┘
   modules/ (8 network)        static/modules/ (4 repo)
              └──────────────┬───────┘
                   ┌─────────▼─────────┐
                   │ web/ (FastAPI)    │  submit → background job →
                   │ app·jobs·service  │  SSE stream → JSON/HTML report
                   └───────────────────┘
```

- Both engines return the **same `ScanResult`** (`core/models.py`), so reporting
  and the web UI are agnostic to which scanner produced the findings.
- Both emit **progress events** via an optional `progress` callback
  (`core/aggregate.py::emit`) that the web layer streams over SSE.
- Module discovery is shared: `core/registry.py::discover_modules(..., base=...)`
  collects either `ScannerModule` (default) or `StaticModule` subclasses. The
  static engine wraps it as `discover_static_modules()`.
- **Execution ordering:** the live engine runs modules in ascending `order`
  tiers, awaiting each tier so correlation modules (`vuln_match`, `order=90`) see
  the inventory populated by discovery modules (`port_scan`/`tls`/`http_headers`
  write `ctx.record_service(...)`).

---

## Project structure

```
vuln-scanner/
├── CLAUDE.md                  # this file
├── README.md                  # user-facing docs
├── pyproject.toml             # packaging, console scripts, [web] extra, pytest config
├── requirements.txt           # core runtime deps
├── requirements-dev.txt       # + pytest, pytest-asyncio
├── requirements-web.txt       # + fastapi, uvicorn (web extra)
├── examples/scope.example.yaml
├── tests/                     # pytest suite (asyncio_mode=auto)
└── vulnscan/
    ├── cli.py                 # argparse CLI, authorization gate, exit codes
    ├── __main__.py            # `python -m vulnscan`
    ├── core/                  # SHARED CONTRACT — change with care
    │   ├── models.py          # Severity, Target, Finding, ScanResult, EXIT_CODES
    │   ├── scope.py           # scope parsing + is_in_scope() enforcement
    │   ├── authorization.py   # the hard authorization gate
    │   ├── module_base.py     # ScannerModule ABC (live module interface)
    │   ├── context.py         # ScanConfig, ScanContext, Inventory
    │   ├── engine.py          # live async engine (tiers, isolation, dedupe)
    │   ├── registry.py        # generic module/plugin discovery (base=...)
    │   ├── aggregate.py       # dedupe_and_sort + progress emit (shared)
    │   ├── ratelimit.py       # token bucket + concurrency cap
    │   ├── versioning.py      # vercmp / version_satisfies (used by SCA + vuln_match)
    │   ├── datafiles.py       # bundled data-file loaders
    │   └── exceptions.py
    ├── modules/               # 8 LIVE modules (auto-discovered)
    │   ├── port_scan.py  tls.py  http_headers.py  dns_checks.py
    │   └── vuln_match.py  exposed_files.py  injection_detect.py  default_creds.py
    ├── static/                # STATIC repository scanner
    │   ├── module_base.py     # StaticModule ABC (repo module interface)
    │   ├── context.py         # RepoContext, RepoMeta, StaticConfig
    │   ├── repo.py            # prepare_repo(): shallow-clone or local folder
    │   ├── engine.py          # StaticEngine + discover_static_modules()
    │   └── modules/           # secrets, dependencies, sensitive_files, code_patterns
    ├── reporting/             # render_console / render_json / render_html (+ write_*)
    ├── plugins/               # drop-in user ScannerModule subclasses
    ├── web/                   # FastAPI dashboard
    │   ├── app.py             # routes + SSE; create_app() factory; module-level `app`
    │   ├── jobs.py            # in-memory JobManager + replayable event log
    │   ├── service.py         # detect_kind, list_modules, run_url_scan, run_repo_scan
    │   ├── __main__.py        # `python -m vulnscan.web`
    │   └── static/            # index.html, app.js, styles.css (Tailwind via CDN)
    └── data/                  # wordlists + signature/secret/dependency/pattern DBs
        ├── subdomains.txt  sensitive_paths.txt  default_creds.json
        └── vuln_signatures.json  secret_patterns.json  dependency_vulns.json  code_patterns.json
```

---

## Key conventions

### Findings
Build every finding via the module's `self.finding(...)` helper (it fills in the
module name). A `Finding` has: `title`, `severity` (`Severity` enum), `description`,
`target` (string), `module`, `evidence` (dict), `remediation`, `references`
(CVE/CWE/URLs), `confidence` (`tentative|firm|confirmed`), and a stable `id`
(SHA-1 of `module|target|title`). Dedup key is `(module, target, title)`.

### Severity & exit codes
`Severity` is an ordered `IntEnum` (`INFO<LOW<MEDIUM<HIGH<CRITICAL`). The process
exit code reflects the highest finding: `0` none/info, `10` Low, `20` Medium,
`30` High, `40` Critical, `1` runtime/auth error (spaced so CI can threshold).

### Adding a LIVE module
Subclass `ScannerModule` in `vulnscan/modules/` (or `vulnscan/plugins/`):
```python
class MyCheck(ScannerModule):
    name = "my_check"; description = "..."; category = "web"
    default_severity = Severity.LOW
    intrusive = False    # True => skipped under --passive
    order = 50           # >50 to run after discovery populates the inventory
    def applicable(self, target, ctx) -> bool: return target.is_web
    async def run(self, target, ctx) -> list[Finding]: ...
```
Do all network I/O through `ctx.http_get/http_request/open_connection` (rate-limited).
Discovery is automatic — no registration.

### Adding a STATIC module
Subclass `StaticModule` in `vulnscan/static/modules/`:
```python
class MyRepoCheck(StaticModule):
    name = "my_repo_check"; description = "..."; category = "sast"
    default_severity = Severity.MEDIUM; order = 40
    def applicable(self, repo) -> bool: return True
    async def run(self, repo) -> list[Finding]: ...
```
Use `repo.iter_files(suffixes=, names=)`, `repo.read_text(path)` (returns `None`
for binary/oversize — skip), `repo.rel(path)`, and
`repo.finding_target(path, line)`. Use `repo.http` only when `repo.has_http`
(offline mode / no client → fall back to bundled data).

### Data files (`vulnscan/data/`)
All checks that ship signatures use feed-updatable JSON: `vuln_signatures.json`
(network CVE correlation), `secret_patterns.json`, `dependency_vulns.json`
(offline SCA fallback; OSV.dev is the primary source), `code_patterns.json`.
Load via `core/datafiles.py` (`load_json` / `load_lines`).

---

## Dev environment & commands

- **Python 3.11+** (this machine: 3.14 in `vuln-scanner/.venv`). This repo lives
  in a multi-project workspace; keep it self-contained in `vuln-scanner/`.
- Use the project venv for everything: `./.venv/Scripts/python.exe` (Windows).

```bash
# install
python -m venv .venv
./.venv/Scripts/python.exe -m pip install -r requirements-dev.txt     # core + tests
./.venv/Scripts/python.exe -m pip install -r requirements-web.txt     # + web (fastapi/uvicorn)

# live CLI
./.venv/Scripts/python.exe -m vulnscan --list-modules
./.venv/Scripts/python.exe -m vulnscan --scope examples/scope.example.yaml --authorize --format all --output report

# web dashboard (http://127.0.0.1:8088)
./.venv/Scripts/python.exe -m vulnscan.web

# tests
./.venv/Scripts/python.exe -m pytest -q
```

The static scanner needs **`git`** on `PATH` to clone remote repos (local-folder
scans don't). The web dashboard requires the `[web]` extra.

---

## Testing

- `pytest` + `pytest-asyncio` in `asyncio_mode=auto` (so `async def test_*` run
  directly). Tests live in `tests/`, are self-contained, and run **offline**.
- HTTP-dependent module tests use `httpx.MockTransport`; the TLS test spins an
  in-process self-signed server; the web test uses `fastapi.testclient.TestClient`
  (guarded by `pytest.importorskip("fastapi")`).
- When changing core models/engine, run the whole suite — the live-engine,
  static-engine, and reporting tests all depend on the shared contract.
- HTML report escaping is security-relevant (findings contain attacker-influenced
  strings): keep all dynamic values `html.escape`-d in `reporting/html_report.py`
  and `textContent`-only in `web/static/app.js`.

---

## Current status

- Live scanner (8 modules), static scanner (4 modules), reporting (console/JSON/
  HTML), CLI, plugin system, and the web dashboard are implemented.
- Test suite green: **90 passed, 1 skipped** (the web-API test skips until the
  `[web]` extra is installed). Install `requirements-web.txt` to enable it and to
  run the dashboard live.
- The dependency SCA module uses live OSV.dev with an offline DB fallback; a live
  end-to-end dashboard smoke-test is the main outstanding verification.

---

## Roadmap

Near-term:
- Live dashboard smoke-test + screenshot once the `[web]` extra is installed.
- Lazy-load FastAPI in `vulnscan/web/__init__.py`/`app.py` so importing the web
  package (and the service layer) doesn't require `fastapi` when only running a
  repo scan programmatically.
- `vulnscan update-db`: refresh `vuln_signatures.json` / `dependency_vulns.json`
  from real feeds (NVD / OSV / GitHub Advisories).

Medium-term:
- Optional same-origin crawler to discover parameters for `injection_detect`
  (currently only scans scope-provided parameterized URLs — no crawling).
- Git-history secret scanning (currently working-tree only).
- Broaden static coverage: more ecosystems for SCA (RubyGems/Packagist/crates.io),
  IaC/Dockerfile checks, optional Semgrep integration for deeper SAST.
- Persist scan jobs/results (currently in-memory) and add report history to the UI.

Longer-term / if deployment scope changes:
- The dashboard is **local/self-hosted by design**. Before any shared/public
  deployment, add authentication, a target allow-list, and stronger rate limiting
  (see the README note) — never ship an open "scan any URL" service.
- Scheduled/recurring scans and diffing between runs (regression gating).
- Pluggable reporters (SARIF for code-scanning integrations, Markdown).
```
