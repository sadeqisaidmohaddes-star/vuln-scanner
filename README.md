# vulnscan

`vulnscan` is a modular, async vulnerability scanner for **authorized** security
assessments. Built for Python 3.11+, it runs a set of independent scanner modules
concurrently — TLS posture analysis, HTTP security-header review, DNS hygiene,
TCP port scanning, sensitive-file exposure, reflected-XSS / error-based SQLi
detection, default-credential checks, and correlation of observed software
versions against a bundled known-vulnerability signature database — and produces
console, JSON, and HTML reports. It is **detection-and-reporting only**: modules
identify misconfigurations, exposures, and known-vulnerable versions and emit
structured findings. They never exploit, exfiltrate data, brute-force, or perform
destructive actions.

Beyond live network scanning, `vulnscan` also ships a **static repository
scanner** — point it at a GitHub repository (or any git URL / local folder) and
it inspects the source for hardcoded secrets, vulnerable dependencies, sensitive
committed files, and risky code patterns. The repo is shallow-cloned to a
temporary directory and only ever **read** — its code is never built, installed,
or executed. A self-hosted **web dashboard** drives both the live and static
scanners from the browser, streaming findings live and offering JSON/HTML report
downloads.

---

## ⚠️ Authorized use only — legal & ethical notice

**This is a security-assessment tool intended ONLY for systems you own or for
which you hold explicit, written authorization to test.** Unauthorized scanning,
probing, or access of computer systems may violate the Computer Fraud and Abuse
Act (US), the Computer Misuse Act (UK), and equivalent laws worldwide, and may
carry civil and criminal penalties. You are solely responsible for your use of
this software. See the [`LICENSE`](LICENSE) file's **AUTHORIZED-USE NOTICE** for
the full statement.

To make this concrete, scanning is blocked behind a hard **authorization gate**
that the engine evaluates before any target is touched:

- You must pass **`--authorize`** on the command line to confirm you hold written
  authorization for the targets, **and**
- When using a scope file, that file must declare **`authorization.authorized: true`**
  with an `authorized_by` value (and the scan is refused once the optional
  `expires` date has passed).

If either input is missing or invalid, the scanner refuses to run. `vulnscan` is
a detection-and-reporting tool — it does not exploit or exfiltrate.

---

## Features

Eight built-in scanner modules (run `python -m vulnscan --list-modules` to see
them live):

| Module | Category | What it does |
| --- | --- | --- |
| `port_scan` | network | Async TCP connect scan with light banner/service/version identification. *Intrusive — skipped under `--passive`.* |
| `http_headers` | web | HTTP security-posture review from a single non-destructive `GET` (security headers, cookie flags, software disclosure, directory listings, error/stack-trace leakage). |
| `tls` | tls | TLS/SSL posture analysis: deprecated protocol enumeration (SSLv3 / TLS 1.0 / 1.1), negotiated cipher, and certificate health (expiry, self-signing, hostname mismatch, weak signature/key). |
| `dns_checks` | dns | DNS hygiene (SPF / DMARC / CAA), a scoped zone-transfer (AXFR) attempt, and wordlist subdomain enumeration. *AXFR + enumeration are intrusive — skipped under `--passive`.* |
| `default_creds` | auth | Bounded check of well-known default credentials against HTTP Basic auth surfaces (one attempt per credential, stops on first success). *Intrusive — skipped under `--passive`.* |
| `exposed_files` | web | Probes a wordlist of sensitive paths (VCS metadata, secrets, backups, admin panels) and reports **reachability only** — never downloads or stores bodies. *Intrusive — skipped under `--passive`.* |
| `injection_detect` | web | Non-destructive detection of reflected-XSS and error-based SQLi signals on scope-provided parameterised URLs (benign canary / single-quote probes only). *Intrusive — skipped under `--passive`.* |
| `vuln_match` | vuln | Passive correlation: matches observed service/product/version against the bundled known-vulnerability signature DB (no network I/O of its own). |

**Reporters** — every scan can emit any combination of:

- **Console** — colorized, severity-sorted terminal summary (Windows-friendly via `colorama`).
- **JSON** — machine-readable report for tooling and CI.
- **HTML** — a standalone, shareable HTML report.

**Plugin system** — drop a `ScannerModule` subclass into `vulnscan/plugins/` (or
point `--plugins-dir` at any directory) and it is discovered and run
automatically, no registration required. See
[`vulnscan/plugins/README.md`](vulnscan/plugins/README.md).

### Static repository scanning

Point `vulnscan` at a **GitHub repository** (or any git URL / local folder) and a
second family of modules analyses the source. The repo is shallow-cloned to a
temporary directory and only ever **read** — its code is never built, installed,
or executed.

| Static module | Category | What it does |
| --- | --- | --- |
| `secrets` | secrets | Scans source for hardcoded credentials (AWS/GCP keys, GitHub/Slack/Stripe tokens, private keys, JWTs, generic secret assignments) and reports them with the matched value **redacted**. |
| `dependencies` | dependency | Software Composition Analysis: parses manifests/lockfiles (`requirements.txt`, `poetry.lock`, `Pipfile.lock`, `package.json`, `package-lock.json`, `pom.xml`, `go.mod`) and matches versions against the live **[OSV.dev](https://osv.dev)** database, with a bundled offline DB as fallback. |
| `sensitive_files` | exposure | Flags files that should never be committed (`.env`, private keys, `*.tfstate`, DB dumps, backups, cloud-credential files), distinguishing real secrets from `.env.example`-style templates. |
| `code_patterns` | sast | Lightweight insecure-code detection (`eval`, `shell=True`, `yaml.load`, `pickle.loads`, disabled TLS verification, weak hashes, `dangerouslySetInnerHTML`, …). |

### Web dashboard

A self-hosted **FastAPI dashboard** drives both the live and static scanners from
the browser: enter a URL or a GitHub repo, watch findings stream in live (grouped
by severity), and download JSON/HTML reports. Live URL scans still require the
authorization attestation; repo scans are read-only static analysis. See the
[Web dashboard](#web-dashboard-1) section below.

---

## Project structure

```
vuln-scanner/
├── vulnscan/
│   ├── __init__.py            # public API: ScannerModule, Finding, Severity, Target, ...
│   ├── __main__.py            # enables `python -m vulnscan`
│   ├── cli.py                 # argument parsing, authorization gate, output, exit codes
│   ├── core/
│   │   ├── authorization.py   # the hard authorization gate (--authorize + scope.authorized)
│   │   ├── context.py         # ScanConfig, ScanContext, Inventory, ServiceObservation
│   │   ├── datafiles.py       # bundled data-file loaders
│   │   ├── engine.py          # async scan engine (scheduling, isolation, dedupe)
│   │   ├── exceptions.py      # VulnScanError, AuthorizationError
│   │   ├── models.py          # Severity, Target, Finding, ScanResult, EXIT_CODES
│   │   ├── module_base.py     # ScannerModule base class
│   │   ├── ratelimit.py       # rate limiting / concurrency cap
│   │   ├── registry.py        # module + plugin discovery
│   │   └── scope.py           # scope parsing and enforcement
│   ├── modules/               # the 8 built-in scanner modules
│   │   ├── port_scan.py
│   │   ├── http_headers.py
│   │   ├── tls.py
│   │   ├── dns_checks.py
│   │   ├── default_creds.py
│   │   ├── exposed_files.py
│   │   ├── injection_detect.py
│   │   └── vuln_match.py
│   ├── plugins/               # drop-in custom modules (see plugins/README.md)
│   ├── reporting/             # console, json_report, html_report renderers
│   ├── static/                # static repository scanner
│   │   ├── context.py         # RepoContext (bounded read-only file access)
│   │   ├── module_base.py     # StaticModule base class
│   │   ├── repo.py            # shallow-clone / local-folder acquisition
│   │   ├── engine.py          # static-scan orchestrator
│   │   └── modules/           # secrets, dependencies, sensitive_files, code_patterns
│   ├── web/                   # FastAPI dashboard
│   │   ├── app.py             # routes (scan submit, SSE stream, report download)
│   │   ├── jobs.py            # in-memory job manager + live event log
│   │   ├── service.py         # bridges the web layer to both engines
│   │   ├── __main__.py        # `python -m vulnscan.web`
│   │   └── static/            # single-page UI (index.html, app.js, styles.css)
│   └── data/                  # bundled wordlists + signature/secret/dependency DBs
│       ├── subdomains.txt
│       ├── sensitive_paths.txt
│       ├── default_creds.json
│       ├── vuln_signatures.json
│       ├── secret_patterns.json
│       ├── dependency_vulns.json
│       └── code_patterns.json
├── examples/
│   └── scope.example.yaml     # documented scope-file template
├── tests/
├── requirements.txt
├── requirements-dev.txt
├── pyproject.toml
├── LICENSE                    # MIT + AUTHORIZED-USE NOTICE
└── README.md
```

---

## Installation

Requires **Python 3.11+**.

```bash
python -m venv .venv
```

Activate the virtual environment:

```powershell
# Windows (PowerShell)
.venv\Scripts\Activate.ps1
```

```bash
# macOS / Linux (POSIX shells)
source .venv/bin/activate
```

Install runtime dependencies:

```bash
pip install -r requirements.txt
```

To run the test suite, also install the dev dependencies (`pytest`,
`pytest-asyncio`):

```bash
pip install -r requirements-dev.txt
```

> Runtime dependencies: `httpx`, `dnspython`, `PyYAML`, `colorama`, and
> `cryptography`.

To run the **web dashboard**, install the optional web extra (adds `fastapi` and
`uvicorn`):

```bash
pip install -r requirements-web.txt
```

The static repository scanner also requires **`git`** to be installed and on your
`PATH` (used to shallow-clone remote repositories; local-folder scans don't need it).

---

## Usage

Invoke as a module (`python -m vulnscan`) or, if installed as a package, via the
`vulnscan` console script.

List the available modules (no scan, no authorization required):

```bash
python -m vulnscan --list-modules
```

Run a full, scope-file-driven engagement and write every report format to
`report.{json,html}`:

```bash
python -m vulnscan --scope examples/scope.example.yaml --authorize --format all --output report
```

Ad-hoc single target(s) with a selected subset of modules:

```bash
python -m vulnscan --target example.com --target 192.0.2.10 --authorize --modules tls,http_headers
```

Passive (non-intrusive) run that skips active modules:

```bash
python -m vulnscan --scope examples/scope.example.yaml --authorize --passive
```

Tune politeness and performance (these override scope-file `settings`):

```bash
python -m vulnscan --scope examples/scope.example.yaml --authorize --rate-limit 5 --concurrency 10
```

### Command-line flags

**Targets & scope**

| Flag | Description |
| --- | --- |
| `--scope FILE` | Path to a YAML/JSON scope file. |
| `--target HOST\|URL` | A single target (repeatable). Adds in-scope entries on top of a `--scope` file, or runs standalone. |

**Module selection**

| Flag | Description |
| --- | --- |
| `--modules LIST` | Comma-separated subset of module names to run (default: all). |
| `--plugins-dir DIR` | Extra directory of plugin modules to load (repeatable). |
| `--list-modules` | List discovered modules and exit. |
| `--passive` | Passive mode: skip intrusive/active modules. |

**Performance & politeness**

| Flag | Default | Description |
| --- | --- | --- |
| `--rate-limit RPS` | `10` | Max requests/sec. |
| `--concurrency N` | `20` | Max concurrent operations. |
| `--timeout SEC` | `10` | Per-operation timeout. |

**Output & reporting**

| Flag | Default | Description |
| --- | --- | --- |
| `--format LIST` | `console` | Comma-separated formats: `console`, `json`, `html`, `all`. |
| `--output PATH` | `vulnscan-report` | Base path for file reports (extension added per format). |
| `--no-color` | | Disable colorized console output. |

**Authorization & misc**

| Flag | Description |
| --- | --- |
| `--authorize` | Confirm you hold explicit written authorization to test these targets. **Required to scan.** |
| `-v`, `--verbose` | Increase log verbosity (`-vv` for debug). |
| `--version` | Print version and exit. |

> Precedence: CLI flags override scope-file `settings`, which override built-in
> defaults.

---

## Scope-file format

A scope file describes one engagement: who authorized it, what is in scope, and
the politeness settings. YAML and JSON are both accepted. A fully documented
template lives at [`examples/scope.example.yaml`](examples/scope.example.yaml).

```yaml
authorization:
  authorized: true                                # REQUIRED: must be true to scan
  authorized_by: "Jane Doe, CISO — Acme Corp"     # REQUIRED: who approved this engagement
  engagement_id: "PT-2026-014"                    # optional, shown in the banner/report
  date: "2026-06-13"                              # optional approval date
  expires: "2026-07-13"                           # optional ISO date; scan refuses to run after it
  notes: "Statement of Work SOW-2026-014, external perimeter assessment."

scope:
  # Hosts, IPs, CIDR ranges, domains, and parameterised URLs are all accepted.
  targets:
    - example.com                                 # domain (DNS + web + TLS)
    - www.example.com
    - 192.0.2.10                                  # single host
    - 192.0.2.0/28                                # CIDR (expanded, capped for safety)
    - https://app.example.com/search?q=test       # URL with a parameter (injection checks)
  exclude:
    - 192.0.2.1                                    # never touched, even if in a range above
  ports: [21, 22, 25, 53, 80, 110, 143, 443, 3306, 5432, 8080, 8443]
  nameservers:
    - ns1.example.com                             # AXFR attempted only against scoped NS

settings:
  rate_limit: 10        # requests per second (CLI --rate-limit overrides)
  concurrency: 20       # max concurrent operations (CLI --concurrency overrides)
  timeout: 10           # per-operation timeout in seconds
  passive: false        # true => skip intrusive modules
```

**Fields**

- `authorization.authorized` — must be `true` or the scan is refused.
- `authorization.authorized_by` — required; identifies who approved the engagement.
- `authorization.engagement_id`, `date`, `notes` — optional metadata, surfaced in the console banner and reports.
- `authorization.expires` — optional ISO date; once the current date is past it, the scan is refused (expiry is enforced).
- `scope.targets` — in-scope hosts, IPs, CIDR ranges, domains, and parameterised URLs.
- `scope.exclude` — entries that are never touched, even if covered by an in-scope range.
- `scope.ports` — the port list used by `port_scan`.
- `scope.nameservers` — nameservers against which the scoped AXFR attempt is made.
- `settings.rate_limit` / `concurrency` / `timeout` / `passive` — defaults for the run; any can be overridden by the corresponding CLI flag.

> Keep real scope files out of version control — the bundled `.gitignore`
> already excludes `scope*.yaml`.

---

## Authorization requirements

Scanning is gated by [`vulnscan/core/authorization.py`](vulnscan/core/authorization.py),
the single chokepoint the engine evaluates **before any target is touched**:

- **Scope-file mode requires BOTH:** `--authorize` on the command line **and**
  `authorization.authorized: true` (with a non-empty `authorized_by`) in the
  scope file. Missing either one aborts the scan.
- **`--target` convenience mode** (no scope file) requires `--authorize` alone;
  the authorization source is recorded as the CLI operator.
- **Expiry is enforced.** If `authorization.expires` is set, the scan is refused
  once the current date is past that ISO date. An unparseable `expires` value is
  also rejected.
- **Scope is enforced before every probe.** Modules cannot reach out to anything
  outside the in-scope set, and `exclude` entries are never touched.
- **`--passive` skips intrusive modules** (`port_scan`, `default_creds`,
  `exposed_files`, `injection_detect`, and the active DNS AXFR / subdomain
  sweep), running only passive, observational checks.

When the gate passes, `vulnscan` prints an authorization banner (who approved it,
engagement id, expiry) plus the legal reminder before scanning.

---

## Output & exit codes

Reports are produced by the renderers in `vulnscan/reporting/`:

- **Console** — always printed; colorized unless `--no-color` or output is not a TTY.
- **JSON** — written to `<output>.json` when `json`/`all` is in `--format`.
- **HTML** — written to `<output>.html` when `html`/`all` is in `--format`.

The process exit code reflects the **highest-severity finding**, so CI pipelines
can gate on it:

| Exit code | Meaning |
| --- | --- |
| `0` | No findings, or only Informational findings |
| `10` | Highest finding is **Low** |
| `20` | Highest finding is **Medium** |
| `30` | Highest finding is **High** |
| `40` | Highest finding is **Critical** |
| `1` | Runtime / configuration error (e.g. authorization refused, bad scope) |

The severity codes are spaced (10/20/30/40) so they never collide with the
conventional `0`/`1`/`2` exit codes, which lets CI gates use simple thresholds.

### CI gating example

Fail the pipeline only when a Medium-or-higher issue is found (`code >= 20`):

```bash
python -m vulnscan --scope engagement.yaml --authorize --format json --output report
code=$?
if [ "$code" -eq 1 ]; then
  echo "scan error"; exit 1
elif [ "$code" -ge 20 ]; then
  echo "Medium+ findings (exit $code) — failing build"; exit "$code"
else
  echo "no gating findings (exit $code)"
fi
```

---

## Writing a plugin

A plugin is any `ScannerModule` subclass. Drop a `.py` file into
`vulnscan/plugins/` (it is discovered automatically) or keep it anywhere and load
it with `--plugins-dir`:

```bash
python -m vulnscan --scope engagement.yaml --authorize --plugins-dir ./my-plugins
```

Minimal sketch:

```python
from vulnscan import ScannerModule, Severity


class RobotsExposure(ScannerModule):
    name = "robots_check"
    description = "Reports whether /robots.txt is present and what it discloses."
    category = "web"
    intrusive = False          # set True for active probing (skipped under --passive)
    order = 50                 # lower runs earlier

    def applicable(self, target, ctx) -> bool:
        return target.is_web

    async def run(self, target, ctx):
        findings = []
        url = target.base_url().rstrip("/") + "/robots.txt"
        try:
            resp = await ctx.http_get(url)
        except Exception:
            return findings
        if resp.status_code == 200:
            findings.append(self.finding(
                title="robots.txt present",
                severity=Severity.INFO,
                description="A robots.txt file is reachable and may disclose paths.",
                target=target,
                evidence={"url": url, "status": resp.status_code},
                remediation="Ensure robots.txt does not reference sensitive paths.",
            ))
        return findings
```

Use `ctx.http_get` / `ctx.http_request` / `ctx.open_connection` so the global
rate limit and concurrency cap are honoured, build findings with
`self.finding(...)`, and honour the detection-only contract — never exfiltrate
data or run destructive payloads. The full interface contract is documented in
[`vulnscan/plugins/README.md`](vulnscan/plugins/README.md).

---

## Updating the vulnerability signature database

The `vuln_match` module correlates observed software against a bundled JSON
signature database at
[`vulnscan/data/vuln_signatures.json`](vulnscan/data/vuln_signatures.json). It is
a small starter set that is **designed to be refreshed from a feed** — extend or
replace it as your CVE coverage needs grow.

The file's top-level shape:

```json
{
  "schema_version": "1.0",
  "updated": "2026-06-13",
  "source": "bundled starter set — replace/extend via an updatable feed",
  "signatures": [
    {
      "id": "VS-0001",
      "product": "OpenSSH",
      "service": "ssh",
      "cpe": "cpe:2.3:a:openbsd:openssh:*",
      "affected": { "version_ge": "8.5", "version_lt": "9.3p2" },
      "cve": "CVE-2023-38408",
      "cwe": "CWE-426",
      "severity": "High",
      "title": "OpenSSH ssh-agent PKCS#11 remote code execution (CVE-2023-38408)",
      "description": "…",
      "references": ["CVE-2023-38408", "https://www.openssh.com/txt/release-9.3p2"]
    }
  ]
}
```

Per-signature fields:

- `id` — stable signature identifier.
- `product` — matched as a **case-insensitive substring** of the observed product name.
- `service` — optional; **case-insensitive exact match** against the observed service.
- `cpe` — optional CPE for cross-referencing.
- `affected` — version constraints, **all of which must hold (logical AND)**:
  - `version_lt` / `version_le` / `version_gt` / `version_ge` — numeric-aware loose comparisons (handle banners like `9.3p2`, `1.3.5a`).
  - `versions` — a list of exact vulnerable version strings.
- `cve`, `cwe` — advisory identifiers.
- `severity` — one of `Info`, `Low`, `Medium`, `High`, `Critical`.
- `title`, `description`, `references` — surfaced on the emitted finding.

To refresh, regenerate the `signatures` array from your chosen vulnerability feed
(keeping this schema) and bump `updated`. Matching is intentionally conservative
and fully offline — a signature only fires when an observed service carries both
a product name and a version that satisfies the constraints.

---

## Web dashboard

The dashboard is a **local, self-hosted** FastAPI app that drives both scanners
from the browser. Install the web extra and start it:

```bash
pip install -r requirements-web.txt
python -m vulnscan.web            # serves http://127.0.0.1:8088
# or, equivalently:
uvicorn vulnscan.web.app:app
```

Then open <http://127.0.0.1:8088> and:

1. **Enter a target** — a web URL (`https://example.com`) or a GitHub repository
   (`owner/repo`, a GitHub URL, or a `.git` URL). The **Auto / URL / Repo** control
   defaults to auto-detection (repo for github/`owner/repo`/`.git`, otherwise a
   live URL scan).
2. **Pick options** (optional) — passive mode, a module subset, and for repos an
   optional private-repo token / git ref.
3. For **live URL scans**, tick **“I am authorized to test this target.”** This is
   the same authorization gate as the CLI — a URL scan submitted without it is
   refused with HTTP `403`. (Repo scans are read-only static analysis, so the
   attestation is recommended but not required.)
4. **Start the scan.** Findings stream in live, grouped by severity, each
   expandable to its description, evidence, remediation, and CVE/CWE references.
   When the scan completes you can **download the JSON or HTML report**.

The server runs scans as background jobs and streams progress over
**Server-Sent Events** (`GET /api/scan/{id}/events`). Other endpoints:
`POST /api/scan`, `GET /api/scan/{id}`, `GET /api/modules`, and
`GET /api/scan/{id}/report.{json,html}`.

> The dashboard is designed for single-user, local use. Because it can drive
> active scans, do not expose it on an untrusted network without adding your own
> authentication and a target allow-list.

---

## Scanning a GitHub repository (static analysis)

Repository scanning runs the four static modules (`secrets`, `dependencies`,
`sensitive_files`, `code_patterns`) over a working tree. You can scan:

- a **GitHub repo** by `owner/repo` shorthand, a full `https://github.com/owner/repo`
  URL, or a `…/owner/repo.git` URL,
- any other **git URL** (GitLab, Bitbucket, self-hosted), or
- a **local folder** path (scanned in place, no clone).

Remote repos are **shallow-cloned** (`git clone --depth 1`) into a temporary
directory that is deleted when the scan finishes. The repository's code is never
built, installed, or executed — modules only read files. Private repositories can
be scanned by supplying a token in the dashboard’s **GitHub token** field (used
solely to authenticate the clone).

**Dependency data sources.** The `dependencies` module first queries the live
**[OSV.dev](https://osv.dev)** API (free, no key) for accurate, up-to-date
advisories. If the host is offline or OSV is unreachable, it falls back to the
bundled offline database. The bundled data files live under `vulnscan/data/`:

- [`secret_patterns.json`](vulnscan/data/secret_patterns.json) — named secret-detection regexes.
- [`dependency_vulns.json`](vulnscan/data/dependency_vulns.json) — offline SCA advisory set (feed-updatable, same version-constraint schema as the signature DB).
- [`code_patterns.json`](vulnscan/data/code_patterns.json) — insecure-code pattern rules.

Findings from a repo scan use a `owner/repo/path/to/file:line` target so you can
jump straight to the offending location. Secrets are always reported **redacted**;
the tool reports *where* a problem is, never the secret value itself.

---

## Running tests

```bash
python -m pytest
```

The suite uses `pytest` with `pytest-asyncio` in `asyncio_mode=auto`, so
`async def test_*` functions run directly. Install dev dependencies first
(`pip install -r requirements-dev.txt`).

---

## Legal & ethical disclaimer

`vulnscan` is provided for **lawful, authorized security testing only**. Use it
exclusively against systems you own or are explicitly, contractually authorized
to assess. Unauthorized scanning may be a criminal offense in your jurisdiction.
The tool detects and reports — it does not exploit — but **you** remain fully
responsible for ensuring you have permission for every target, for staying within
the agreed scope and time window, and for complying with all applicable laws and
the terms of your engagement. The software is provided "as is", without warranty
of any kind; see [`LICENSE`](LICENSE) for the full terms and the AUTHORIZED-USE
NOTICE.
