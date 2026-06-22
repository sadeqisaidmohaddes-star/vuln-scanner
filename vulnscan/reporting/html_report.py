"""Standalone HTML reporter for :class:`~vulnscan.core.models.ScanResult`.

This module renders a single, self-contained HTML document (all CSS inlined,
no external assets, no scripts) summarising a completed scan. It is a *pure*
reporter: :func:`render_html` has no side effects and returns a string, while
:func:`write_html` is the only function that touches the filesystem (writing
the rendered document as UTF-8).

Security note
-------------
Findings carry attacker-influenced data (titles, evidence, targets, header
values harvested from remote hosts, ...). Every dynamic value placed into the
document is escaped with :func:`html.escape` before interpolation, including
the text and ``href`` of generated links, so the report is safe to open even
when scanning a hostile target.
"""
from __future__ import annotations

import html
import json
import re
from pathlib import Path
from typing import Any

from vulnscan.core.models import ScanResult, Severity

__all__ = ["render_html", "write_html"]

#: Tool version surfaced in the report header. Kept local so the reporter has
#: no import-time dependency on package metadata that may not be installed.
_TOOL_NAME = "vulnscan"
_TOOL_VERSION = "1.0"

#: Hex colours for each severity badge, keyed by the human label.
_SEVERITY_COLORS: dict[str, str] = {
    "Critical": "#b00020",
    "High": "#d9534f",
    "Medium": "#f0ad4e",
    "Low": "#5bc0de",
    "Info": "#777",
}

#: Severity labels ordered most-severe-first, used for grouping/sorting.
_SEVERITY_ORDER: list[str] = [sev.label for sev in sorted(Severity, reverse=True)]

# Reference recognisers. ``fullmatch`` is used against the stripped reference so
# only references that are *entirely* an identifier are linkified as such.
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)
_URL_RE = re.compile(r"https?://", re.IGNORECASE)


def _esc(value: Any) -> str:
    """Escape an arbitrary value for safe inclusion in HTML text/attributes.

    ``None`` becomes the empty string; everything else is stringified and then
    passed through :func:`html.escape` (which also escapes quotes), making the
    result safe in both element bodies and double-quoted attribute values.
    """
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _severity_color(label: str) -> str:
    """Return the badge colour for a severity label (defaulting to Info grey)."""
    return _SEVERITY_COLORS.get(label, _SEVERITY_COLORS["Info"])


def _badge(label: str) -> str:
    """Render a coloured, escaped severity badge ``<span>``."""
    color = _severity_color(label)
    return (
        f'<span class="badge" style="background:{color}">'
        f"{_esc(label)}</span>"
    )


def _render_reference(ref: str) -> str:
    """Render a single reference, linkifying CVE/CWE ids and bare URLs.

    The returned HTML is fully escaped: link hrefs and text are passed through
    :func:`_esc`, so a malicious reference cannot break out of the attribute or
    inject markup. References that are neither a recognised identifier nor a URL
    are emitted as plain escaped text.
    """
    text = str(ref).strip()
    if not text:
        return ""

    cve = _CVE_RE.fullmatch(text)
    if cve:
        cve_id = cve.group(0).upper()
        href = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        return f'<a href="{_esc(href)}" rel="noreferrer noopener">{_esc(cve_id)}</a>'

    cwe = _CWE_RE.fullmatch(text)
    if cwe:
        number = cwe.group(1)
        href = f"https://cwe.mitre.org/data/definitions/{number}.html"
        return (
            f'<a href="{_esc(href)}" rel="noreferrer noopener">'
            f"{_esc('CWE-' + number)}</a>"
        )

    if _URL_RE.match(text):
        return f'<a href="{_esc(text)}" rel="noreferrer noopener">{_esc(text)}</a>'

    return _esc(text)


def _render_evidence(evidence: dict[str, Any]) -> str:
    """Render a finding's evidence dict as an escaped definition list.

    Scalar values are shown as key/value rows; nested/complex values are
    rendered as pretty-printed JSON inside a ``<pre>`` block. If JSON
    serialisation fails for any reason, ``repr`` is used as a safe fallback.
    All output is escaped.
    """
    if not evidence:
        return '<p class="muted">No evidence recorded.</p>'

    rows: list[str] = []
    for key, value in evidence.items():
        if isinstance(value, (str, int, float, bool)) or value is None:
            rendered = f'<span class="ev-value">{_esc(value)}</span>'
        else:
            try:
                blob = json.dumps(value, indent=2, default=str, sort_keys=True)
            except (TypeError, ValueError):  # pragma: no cover - defensive
                blob = repr(value)
            rendered = f"<pre>{_esc(blob)}</pre>"
        rows.append(
            '<div class="ev-row">'
            f'<span class="ev-key">{_esc(key)}</span>{rendered}</div>'
        )
    return '<div class="evidence">' + "".join(rows) + "</div>"


def _render_finding(data: dict[str, Any]) -> str:
    """Render one finding (from :meth:`Finding.to_dict`) as an HTML card."""
    label = str(data.get("severity", "Info"))
    color = _severity_color(label)

    references = data.get("references") or []
    if references:
        items = "".join(
            f"<li>{_render_reference(ref)}</li>" for ref in references
        )
        refs_html = f'<ul class="refs">{items}</ul>'
    else:
        refs_html = '<p class="muted">None.</p>'

    remediation = str(data.get("remediation") or "").strip()
    remediation_html = (
        f"<p>{_esc(remediation)}</p>"
        if remediation
        else '<p class="muted">No remediation provided.</p>'
    )

    description = str(data.get("description") or "").strip()
    description_html = (
        f"<p>{_esc(description)}</p>"
        if description
        else '<p class="muted">No description provided.</p>'
    )

    return f"""
    <article class="finding" style="border-left-color:{color}">
      <header class="finding-head">
        {_badge(label)}
        <h3 class="finding-title">{_esc(data.get("title"))}</h3>
        <span class="finding-id">#{_esc(data.get("id"))}</span>
      </header>
      <div class="meta-grid">
        <div><span class="meta-label">Target</span>{_esc(data.get("target"))}</div>
        <div><span class="meta-label">Module</span>{_esc(data.get("module"))}</div>
        <div><span class="meta-label">Confidence</span>{_esc(data.get("confidence"))}</div>
      </div>
      <section class="finding-section">
        <h4>Description</h4>
        {description_html}
      </section>
      <section class="finding-section">
        <h4>Evidence</h4>
        {_render_evidence(data.get("evidence") or {})}
      </section>
      <section class="finding-section">
        <h4>Remediation</h4>
        {remediation_html}
      </section>
      <section class="finding-section">
        <h4>References</h4>
        {refs_html}
      </section>
    </article>"""


def _render_summary(result: ScanResult) -> str:
    """Render the executive-summary badges/counts block."""
    counts = result.counts
    cards: list[str] = []
    for label in _SEVERITY_ORDER:
        count = counts.get(label, 0)
        color = _severity_color(label)
        cards.append(
            f'<div class="count-card" style="border-top-color:{color}">'
            f'<span class="count-num" style="color:{color}">{count}</span>'
            f'<span class="count-label">{_esc(label)}</span></div>'
        )

    highest = result.highest.label
    return f"""
    <section class="summary">
      <h2>Executive Summary</h2>
      <div class="summary-stats">
        <div class="stat">
          <span class="stat-num">{len(result.findings)}</span>
          <span class="stat-label">Total Findings</span>
        </div>
        <div class="stat">
          {_badge(highest)}
          <span class="stat-label">Highest Severity</span>
        </div>
        <div class="stat">
          <span class="stat-num">{len(result.errors)}</span>
          <span class="stat-label">Module Errors</span>
        </div>
      </div>
      <div class="count-grid">{"".join(cards)}</div>
    </section>"""


def _render_findings_section(result: ScanResult) -> str:
    """Render all findings, grouped by severity from Critical down to Info."""
    if not result.findings:
        return (
            '<section class="findings"><h2>Findings</h2>'
            '<p class="empty">No findings were reported. '
            "All executed checks completed without identifying an issue.</p>"
            "</section>"
        )

    # Bucket findings by severity label, then sort each bucket by title for
    # stable, readable output.
    buckets: dict[str, list[dict[str, Any]]] = {label: [] for label in _SEVERITY_ORDER}
    for finding in result.findings:
        data = finding.to_dict()
        buckets.setdefault(str(data.get("severity", "Info")), []).append(data)

    groups: list[str] = []
    for label in _SEVERITY_ORDER:
        bucket = buckets.get(label) or []
        if not bucket:
            continue
        bucket.sort(key=lambda d: str(d.get("title", "")).lower())
        color = _severity_color(label)
        cards = "".join(_render_finding(item) for item in bucket)
        groups.append(
            f'<div class="severity-group">'
            f'<h3 class="group-head" style="color:{color}">'
            f"{_esc(label)} <span class=\"group-count\">({len(bucket)})</span></h3>"
            f"{cards}</div>"
        )

    return f'<section class="findings"><h2>Findings</h2>{"".join(groups)}</section>'


def _render_errors_section(result: ScanResult) -> str:
    """Render the module-errors section, or empty string when there are none."""
    if not result.errors:
        return ""

    rows: list[str] = []
    for error in result.errors:
        if isinstance(error, dict):
            module = error.get("module") or error.get("source") or "-"
            message = error.get("error") or error.get("message") or str(error)
        else:  # pragma: no cover - defensive against loose typing
            module, message = "-", str(error)
        rows.append(
            f"<tr><td>{_esc(module)}</td><td>{_esc(message)}</td></tr>"
        )

    return f"""
    <section class="errors">
      <h2>Module Errors</h2>
      <p class="muted">The following modules failed to run cleanly. Their
      findings (if any) may be incomplete.</p>
      <table class="error-table">
        <thead><tr><th>Module</th><th>Error</th></tr></thead>
        <tbody>{"".join(rows)}</tbody>
      </table>
    </section>"""


def _render_header(result: ScanResult) -> str:
    """Render the document header with scan metadata and scope details."""
    scope = result.scope_summary or {}
    engagement = scope.get("engagement_id") or scope.get("engagement") or scope.get("name") or "-"
    authorized_by = scope.get("authorized_by") or scope.get("authorised_by") or "-"

    meta_rows = [
        ("Started", result.started_at or "-"),
        ("Finished", result.finished_at or "-"),
        ("Duration", f"{result.duration_seconds:.2f}s"),
        ("Targets scanned", result.targets_scanned),
        ("Modules run", ", ".join(result.modules_run) if result.modules_run else "-"),
        ("Engagement", engagement),
        ("Authorized by", authorized_by),
    ]
    rows = "".join(
        f'<div class="hdr-row"><span class="hdr-key">{_esc(key)}</span>'
        f'<span class="hdr-val">{_esc(value)}</span></div>'
        for key, value in meta_rows
    )

    return f"""
    <header class="report-header">
      <div class="brand">
        <span class="tool-name">{_esc(_TOOL_NAME)}</span>
        <span class="tool-version">v{_esc(_TOOL_VERSION)}</span>
      </div>
      <h1>Vulnerability Scan Report</h1>
      <div class="hdr-grid">{rows}</div>
    </header>"""


_STYLE = """
:root {
  --bg: #f6f7f9;
  --fg: #1d2127;
  --muted: #6b7280;
  --card: #ffffff;
  --border: #e3e6ea;
  --accent: #2d3748;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--fg);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
    Helvetica, Arial, sans-serif;
  line-height: 1.5;
  font-size: 15px;
}
.wrap { max-width: 980px; margin: 0 auto; padding: 32px 20px 64px; }
h1 { font-size: 26px; margin: 8px 0 20px; }
h2 { font-size: 20px; margin: 0 0 16px; border-bottom: 2px solid var(--border);
  padding-bottom: 8px; }
h3 { font-size: 16px; margin: 0; }
h4 { font-size: 12px; text-transform: uppercase; letter-spacing: .05em;
  color: var(--muted); margin: 0 0 6px; }
p { margin: 0 0 8px; }
section { margin-bottom: 36px; }
.muted { color: var(--muted); font-style: italic; }

.report-header {
  background: var(--accent);
  color: #fff;
  border-radius: 12px;
  padding: 24px 28px;
  margin-bottom: 36px;
}
.report-header h1 { color: #fff; }
.brand { display: flex; align-items: baseline; gap: 10px; }
.tool-name { font-size: 20px; font-weight: 700; letter-spacing: .02em; }
.tool-version { font-size: 13px; opacity: .75; }
.hdr-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
  gap: 6px 24px;
}
.hdr-row { display: flex; justify-content: space-between; gap: 12px;
  padding: 4px 0; border-bottom: 1px solid rgba(255,255,255,.12); }
.hdr-key { opacity: .7; }
.hdr-val { font-weight: 600; text-align: right; word-break: break-word; }

.badge {
  display: inline-block;
  color: #fff;
  font-size: 12px;
  font-weight: 700;
  padding: 2px 10px;
  border-radius: 999px;
  letter-spacing: .03em;
  white-space: nowrap;
}

.summary-stats { display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 20px; }
.stat {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 14px 20px;
  min-width: 150px;
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.stat-num { font-size: 28px; font-weight: 800; line-height: 1; }
.stat-label { font-size: 12px; color: var(--muted); text-transform: uppercase;
  letter-spacing: .04em; }

.count-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 12px;
}
.count-card {
  background: var(--card);
  border: 1px solid var(--border);
  border-top: 4px solid var(--muted);
  border-radius: 10px;
  padding: 14px;
  text-align: center;
}
.count-num { display: block; font-size: 30px; font-weight: 800; line-height: 1; }
.count-label { font-size: 12px; color: var(--muted); text-transform: uppercase;
  letter-spacing: .04em; }

.severity-group { margin-bottom: 24px; }
.group-head { margin: 0 0 12px; font-size: 17px; }
.group-count { color: var(--muted); font-weight: 500; font-size: 14px; }

.finding {
  background: var(--card);
  border: 1px solid var(--border);
  border-left: 5px solid var(--muted);
  border-radius: 10px;
  padding: 18px 20px;
  margin-bottom: 16px;
}
.finding-head { display: flex; align-items: center; gap: 12px;
  flex-wrap: wrap; margin-bottom: 12px; }
.finding-title { flex: 1; min-width: 200px; }
.finding-id { font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas,
  monospace; font-size: 12px; color: var(--muted); }
.meta-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 8px 16px;
  background: var(--bg);
  border-radius: 8px;
  padding: 10px 14px;
  margin-bottom: 14px;
  font-size: 14px;
  word-break: break-word;
}
.meta-label { display: block; font-size: 11px; text-transform: uppercase;
  letter-spacing: .04em; color: var(--muted); }
.finding-section { margin-bottom: 14px; }
.finding-section:last-child { margin-bottom: 0; }

.evidence { display: flex; flex-direction: column; gap: 6px; }
.ev-row { display: flex; flex-direction: column; gap: 2px; }
.ev-key { font-weight: 600; font-size: 13px; }
.ev-value { word-break: break-word; }
pre {
  background: #1d2127;
  color: #e6edf3;
  padding: 12px 14px;
  border-radius: 8px;
  overflow-x: auto;
  font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
  font-size: 13px;
  margin: 4px 0 0;
  white-space: pre-wrap;
  word-break: break-word;
}
.refs { margin: 0; padding-left: 20px; }
.refs li { word-break: break-word; }
a { color: #1a64c4; text-decoration: none; }
a:hover { text-decoration: underline; }

.error-table { width: 100%; border-collapse: collapse; font-size: 14px; }
.error-table th, .error-table td {
  text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--border);
  vertical-align: top; word-break: break-word;
}
.error-table th { background: var(--bg); font-size: 12px; text-transform: uppercase;
  letter-spacing: .04em; color: var(--muted); }

.empty {
  background: var(--card);
  border: 1px dashed var(--border);
  border-radius: 10px;
  padding: 24px;
  text-align: center;
  color: var(--muted);
}

footer {
  margin-top: 48px;
  padding-top: 16px;
  border-top: 1px solid var(--border);
  font-size: 12px;
  color: var(--muted);
  text-align: center;
}
""".strip()


_FOOTER = (
    "<footer>This report is an artifact of an authorized security assessment "
    "and is intended solely for the engaged parties. "
    f"{_esc(_TOOL_NAME)} is a detection-only tool: it identifies and reports "
    "potential issues and performs no exploitation or modification of the "
    "scanned targets.</footer>"
)


def render_html(result: ScanResult) -> str:
    """Render a :class:`ScanResult` as a single self-contained HTML document.

    The returned string is a complete HTML5 document with all CSS inlined and
    no external assets or scripts. It is a pure function with no side effects,
    and renders correctly even when ``result`` contains zero findings and/or
    zero errors.

    :param result: The completed scan result to render.
    :returns: A standalone HTML document as a string.
    """
    body = "".join(
        [
            _render_header(result),
            _render_summary(result),
            _render_findings_section(result),
            _render_errors_section(result),
            _FOOTER,
        ]
    )

    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{_esc(_TOOL_NAME)} scan report</title>\n"
        f"<style>{_STYLE}</style>\n"
        "</head>\n"
        "<body>\n"
        f'<div class="wrap">{body}</div>\n'
        "</body>\n"
        "</html>\n"
    )


def write_html(result: ScanResult, path: str | Path) -> None:
    """Render ``result`` to HTML and write it to ``path`` as UTF-8.

    This is the only function in this module that performs I/O. Parent
    directories are *not* created automatically; the caller is responsible for
    ensuring the target directory exists.

    :param result: The completed scan result to render.
    :param path: Destination file path (``str`` or :class:`~pathlib.Path`).
    """
    document = render_html(result)
    Path(path).write_text(document, encoding="utf-8")
