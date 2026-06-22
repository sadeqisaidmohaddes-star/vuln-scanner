"""Human-readable terminal report for a :class:`~vulnscan.core.models.ScanResult`.

:func:`render_console` is a pure function: it takes a finished scan result and
returns a printable string (the CLI is responsible for actually writing it to
stdout). It performs no network access and no file I/O.

Colour is provided by :mod:`colorama` when available so that ANSI codes render
correctly on legacy Windows consoles. The import is guarded: if colorama is not
installed the renderer simply degrades to plain, uncoloured output. When the
caller passes ``use_color=False`` no ANSI escape codes are emitted at all.
"""
from __future__ import annotations

import textwrap
from typing import Optional

from ..core.models import ScanResult, Severity

# ---------------------------------------------------------------------------
# Optional colorama support.
#
# We pull the colour constants we need out of colorama if it is importable and
# fix up the Windows console so ANSI sequences are interpreted. If anything goes
# wrong (module missing, init failure) we fall back to empty strings, which makes
# every styling helper a no-op without any special-casing at the call sites.
# ---------------------------------------------------------------------------
try:  # pragma: no cover - exercised implicitly depending on environment
    import colorama
    from colorama import Fore, Style

    # ``just_fix_windows_console`` is the modern, idempotent entry point; fall
    # back to the classic ``init`` on older colorama releases.
    _fix = getattr(colorama, "just_fix_windows_console", None)
    if _fix is not None:
        _fix()
    else:  # pragma: no cover - depends on installed colorama version
        colorama.init()

    _RESET = Style.RESET_ALL
    _BRIGHT = Style.BRIGHT
    _DIM = Style.DIM
    _RED = Fore.RED
    _YELLOW = Fore.YELLOW
    _CYAN = Fore.CYAN
    _WHITE = Fore.WHITE
    _GREEN = Fore.GREEN
    _COLORAMA_OK = True
except Exception:  # noqa: BLE001 - any import/init failure means "no colour"
    _RESET = _BRIGHT = _DIM = _RED = _YELLOW = _CYAN = _WHITE = _GREEN = ""
    _COLORAMA_OK = False


# Per-severity colour prefixes (combined escape sequences). These map directly to
# the project's required palette:
#   Critical -> bright red, High -> red, Medium -> yellow, Low -> cyan,
#   Info -> dim/white.
_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: _BRIGHT + _RED,
    Severity.HIGH: _RED,
    Severity.MEDIUM: _YELLOW,
    Severity.LOW: _CYAN,
    Severity.INFO: _DIM + _WHITE,
}

# Target line width for wrapped prose. Kept a touch under 100 columns so the
# indented continuation lines still sit comfortably inside a standard terminal.
_WIDTH = 100
_INDENT = "    "


def _colorize(text: str, style: str, *, use_color: bool) -> str:
    """Wrap ``text`` in ``style`` + reset, or return it unchanged.

    Returns ``text`` verbatim when colour is disabled, colorama is unavailable,
    or ``style`` is empty, guaranteeing no stray escape codes leak into plain
    output.
    """
    if not use_color or not _COLORAMA_OK or not style:
        return text
    return f"{style}{text}{_RESET}"


def _severity_tag(severity: Severity, *, use_color: bool) -> str:
    """Render a fixed-width, optionally coloured ``[SEVERITY]`` tag."""
    tag = f"[{severity.label.upper():^8}]"
    return _colorize(tag, _SEVERITY_STYLE.get(severity, ""), use_color=use_color)


def _wrap_block(label: str, body: str, *, use_color: bool) -> list[str]:
    """Wrap ``body`` under an indented, optionally bold ``label:`` heading.

    Returns an empty list when ``body`` is blank so callers can splice the result
    in unconditionally without producing empty sections.
    """
    body = (body or "").strip()
    if not body:
        return []
    heading = _colorize(f"{label}:", _BRIGHT, use_color=use_color)
    lines = [f"{_INDENT}{heading}"]
    wrapper = textwrap.TextWrapper(
        width=_WIDTH,
        initial_indent=_INDENT * 2,
        subsequent_indent=_INDENT * 2,
        break_long_words=False,
        break_on_hyphens=False,
    )
    for paragraph in body.splitlines() or [body]:
        paragraph = paragraph.strip()
        if paragraph:
            lines.extend(wrapper.wrap(paragraph))
        else:
            lines.append("")
    return lines


def _render_finding(finding, *, use_color: bool) -> list[str]:
    """Render a single finding into a list of output lines."""
    lines: list[str] = []
    tag = _severity_tag(finding.severity, use_color=use_color)
    title = _colorize(finding.title, _BRIGHT, use_color=use_color)
    lines.append(f"{tag} {title}")

    # Provenance line: target | module | id  (and confidence for context).
    meta = f"{finding.target} | {finding.module} | {finding.id}"
    if finding.confidence:
        meta += f" | confidence={finding.confidence}"
    lines.append(_colorize(f"{_INDENT}{meta}", _DIM, use_color=use_color))

    lines.extend(_wrap_block("Description", finding.description, use_color=use_color))
    lines.extend(_wrap_block("Remediation", finding.remediation, use_color=use_color))

    if finding.references:
        refs = ", ".join(str(r) for r in finding.references)
        lines.extend(_wrap_block("References", refs, use_color=use_color))

    lines.append("")  # blank separator between findings
    return lines


def _render_summary(result: ScanResult, *, use_color: bool) -> list[str]:
    """Render the SUMMARY block (per-severity counts plus run metadata)."""
    counts = result.counts
    parts = [
        _colorize(
            f"{sev.label}: {counts.get(sev.label, 0)}",
            _SEVERITY_STYLE.get(sev, ""),
            use_color=use_color,
        )
        for sev in sorted(Severity, reverse=True)
    ]

    lines = [_colorize("SUMMARY", _BRIGHT, use_color=use_color)]
    lines.append(_INDENT + "  ".join(parts))

    highest_style = _SEVERITY_STYLE.get(result.highest, "")
    highest = _colorize(result.highest.label, highest_style, use_color=use_color)
    lines.append(
        f"{_INDENT}Total findings: {len(result.findings)}   "
        f"Highest severity: {highest}"
    )
    lines.append(
        f"{_INDENT}Targets scanned: {result.targets_scanned}   "
        f"Duration: {result.duration_seconds:.2f}s   "
        f"Module errors: {len(result.errors)}"
    )
    return lines


def _render_errors(result: ScanResult, *, use_color: bool) -> list[str]:
    """Render the optional Errors section listing failed module runs."""
    if not result.errors:
        return []
    heading = _colorize(
        f"Errors ({len(result.errors)})", _BRIGHT + _YELLOW, use_color=use_color
    )
    lines = ["", heading]
    for err in result.errors:
        module = err.get("module", "?")
        target = err.get("target", "?")
        message = err.get("error", "")
        lines.append(f"{_INDENT}{module} | {target}")
        if message:
            wrapper = textwrap.TextWrapper(
                width=_WIDTH,
                initial_indent=_INDENT * 2,
                subsequent_indent=_INDENT * 2,
                break_long_words=False,
                break_on_hyphens=False,
            )
            lines.extend(wrapper.wrap(message.strip()))
    return lines


def render_console(result: ScanResult, *, use_color: bool = True) -> str:
    """Render a scan result as a printable, optionally colourised report.

    The output contains a header line, a SUMMARY block (per-severity counts,
    total findings, highest severity, targets scanned, duration and the count of
    module errors), the findings grouped by severity from Critical down to Info,
    and finally an Errors section if any module runs failed.

    Args:
        result: The completed :class:`~vulnscan.core.models.ScanResult` to render.
        use_color: When ``True`` (the default) and :mod:`colorama` is available,
            ANSI colour codes are emitted. When ``False`` the output is plain text
            with no escape sequences whatsoever.

    Returns:
        The full report as a single ``str`` ready to be printed.
    """
    # Colour is only ever applied when explicitly requested *and* colorama loaded.
    use_color = use_color and _COLORAMA_OK

    lines: list[str] = []
    header = _colorize("vulnscan report", _BRIGHT, use_color=use_color)
    lines.append(header)
    lines.append("=" * len(header) if not use_color else "=" * len("vulnscan report"))
    lines.append("")

    lines.extend(_render_summary(result, use_color=use_color))
    lines.append("")

    if not result.findings:
        lines.append(_colorize("No findings.", _GREEN, use_color=use_color))
    else:
        # Group findings by severity, Critical -> Info; within a group keep the
        # engine's existing ordering (it already ranks findings).
        by_severity: dict[Severity, list] = {sev: [] for sev in Severity}
        for finding in result.findings:
            by_severity[finding.severity].append(finding)

        for severity in sorted(Severity, reverse=True):
            group = by_severity[severity]
            if not group:
                continue
            group_style = _SEVERITY_STYLE.get(severity, "")
            heading = _colorize(
                f"{severity.label.upper()} ({len(group)})",
                _BRIGHT + group_style if group_style else _BRIGHT,
                use_color=use_color,
            )
            lines.append(heading)
            lines.append("")
            for finding in group:
                lines.extend(_render_finding(finding, use_color=use_color))

    error_lines = _render_errors(result, use_color=use_color)
    if error_lines:
        lines.extend(error_lines)

    # Trim a trailing blank line for tidy output but keep a final newline-friendly
    # string.
    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines)
