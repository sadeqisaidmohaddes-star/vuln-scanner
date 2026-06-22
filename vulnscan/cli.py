"""Command-line interface for vulnscan.

Examples
--------
    # Scope-file driven (recommended); requires authorization.authorized: true
    vulnscan --scope engagement.yaml --authorize --format console,html --output report

    # Ad-hoc single target (authorization asserted via --authorize)
    vulnscan --target example.com --authorize --modules tls,http_headers

    # List available modules (no scan, no authorization needed)
    vulnscan --list-modules
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path
from typing import Optional, Sequence

from . import __version__
from .core.context import ScanConfig
from .core.engine import ScanEngine
from .core.exceptions import VulnScanError
from .core.registry import discover_modules
from .core.scope import Scope

LEGAL_REMINDER = (
    "vulnscan is for AUTHORIZED testing only. Scanning systems without explicit "
    "written permission may be illegal. You are responsible for your use."
)


# --------------------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnscan",
        description=(
            "Modular vulnerability scanner for AUTHORIZED security assessments. "
            "Detection and reporting only — it does not exploit or exfiltrate."
        ),
        epilog=LEGAL_REMINDER,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    tgt = parser.add_argument_group("targets & scope")
    tgt.add_argument("--scope", metavar="FILE", help="Path to a YAML/JSON scope file (see README).")
    tgt.add_argument(
        "--target",
        action="append",
        default=[],
        metavar="HOST|URL",
        help="A single target (repeatable). Mutually informative with --scope.",
    )

    mod = parser.add_argument_group("module selection")
    mod.add_argument(
        "--modules",
        metavar="LIST",
        help="Comma-separated subset of module names to run (default: all).",
    )
    mod.add_argument(
        "--plugins-dir",
        action="append",
        default=[],
        metavar="DIR",
        help="Extra directory of plugin modules to load (repeatable).",
    )
    mod.add_argument("--list-modules", action="store_true", help="List discovered modules and exit.")
    mod.add_argument(
        "--passive",
        action="store_true",
        help="Passive mode: skip intrusive/active modules (port scan, injection, default creds).",
    )

    perf = parser.add_argument_group("performance & politeness")
    perf.add_argument("--rate-limit", type=float, metavar="RPS", help="Max requests/sec (default: 10).")
    perf.add_argument("--concurrency", type=int, metavar="N", help="Max concurrent operations (default: 20).")
    perf.add_argument("--timeout", type=float, metavar="SEC", help="Per-operation timeout (default: 10).")

    out = parser.add_argument_group("output & reporting")
    out.add_argument(
        "--format",
        default="console",
        metavar="LIST",
        help="Comma-separated output formats: console, json, html, all (default: console).",
    )
    out.add_argument(
        "--output",
        metavar="PATH",
        help="Base path for file reports (extension added per format). Default: vulnscan-report",
    )
    out.add_argument("--no-color", action="store_true", help="Disable colorized console output.")

    auth = parser.add_argument_group("authorization (required to scan)")
    auth.add_argument(
        "--authorize",
        action="store_true",
        help="Confirm you hold explicit written authorization to test these targets.",
    )

    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase log verbosity (-vv for debug).")
    parser.add_argument("--version", action="version", version=f"vulnscan {__version__}")
    return parser


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------

def _configure_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)


def _build_scope(args: argparse.Namespace) -> Scope:
    if args.scope:
        scope = Scope.from_file(args.scope)
        # --target adds extra in-scope entries on top of the file.
        if args.target:
            scope.includes.extend(args.target)
            scope._index(args.target, scope._inc_networks, scope._inc_hosts, scope._inc_domains)
        return scope
    if args.target:
        return Scope.from_targets(args.target, authorized_via_cli=args.authorize)
    raise VulnScanError("No targets given. Provide --scope FILE and/or --target HOST.")


def _resolve_config(args: argparse.Namespace, scope: Scope) -> ScanConfig:
    """CLI flags override scope-file settings, which override built-in defaults."""
    s = scope.settings or {}

    def pick(cli_value, key, default):
        if cli_value is not None:
            return cli_value
        if key in s:
            return s[key]
        return default

    return ScanConfig(
        rate_limit=float(pick(args.rate_limit, "rate_limit", 10.0)),
        concurrency=int(pick(args.concurrency, "concurrency", 20)),
        timeout=float(pick(args.timeout, "timeout", 10.0)),
        passive=bool(args.passive or s.get("passive", False)),
        verbose=args.verbose > 0,
        extra=s.get("modules", {}) if isinstance(s.get("modules"), dict) else {},
    )


def _parse_formats(value: str) -> list[str]:
    formats = {f.strip().lower() for f in (value or "").split(",") if f.strip()}
    if "all" in formats:
        return ["console", "json", "html"]
    valid = {"console", "json", "html"}
    unknown = formats - valid
    if unknown:
        raise VulnScanError(f"Unknown output format(s): {', '.join(sorted(unknown))}")
    return [f for f in ("console", "json", "html") if f in formats] or ["console"]


def _print_banner(scope: Scope) -> None:
    bar = "=" * 64
    print(bar, file=sys.stderr)
    print(scope.authorization.banner(), file=sys.stderr)
    print(f"  {LEGAL_REMINDER}", file=sys.stderr)
    print(bar, file=sys.stderr)


# --------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------

def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    _configure_logging(args.verbose)
    log = logging.getLogger("vulnscan")

    # --list-modules needs no scope or authorization.
    if args.list_modules:
        modules = discover_modules(extra_dirs=args.plugins_dir)
        print(f"Discovered {len(modules)} module(s):\n")
        for m in modules:
            flag = " [intrusive]" if m.intrusive else ""
            print(f"  {m.name:<16} {m.category:<10} {m.description}{flag}")
        return 0

    try:
        scope = _build_scope(args)
        # --- the hard authorization gate -------------------------------------------
        scope.authorization.require(args.authorize)
        formats = _parse_formats(args.format)
        config = _resolve_config(args, scope)
    except VulnScanError as exc:
        log.error("%s", exc)
        return 1

    _print_banner(scope)

    try:
        modules = discover_modules(extra_dirs=args.plugins_dir)
        engine = ScanEngine(scope, config, modules, log=log)
        module_names = [m.strip() for m in args.modules.split(",")] if args.modules else None
        result = asyncio.run(engine.run(module_names))
    except VulnScanError as exc:
        log.error("%s", exc)
        return 1
    except KeyboardInterrupt:  # pragma: no cover
        log.error("Interrupted by user.")
        return 1

    # Import reporters lazily so --list-modules etc. stay dependency-light.
    from .reporting import render_console, write_html, write_json

    use_color = (not args.no_color) and sys.stdout.isatty()
    print(render_console(result, use_color=use_color))

    base = Path(args.output) if args.output else Path("vulnscan-report")
    if "json" in formats:
        json_path = base.with_suffix(".json")
        write_json(result, json_path)
        print(f"[+] JSON report written to {json_path}", file=sys.stderr)
    if "html" in formats:
        html_path = base.with_suffix(".html")
        write_html(result, html_path)
        print(f"[+] HTML report written to {html_path}", file=sys.stderr)

    if result.errors:
        log.warning("%d module run(s) failed; see report 'errors' section.", len(result.errors))

    return result.exit_code()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
