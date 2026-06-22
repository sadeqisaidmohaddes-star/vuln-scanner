"""Run the dashboard: ``python -m vulnscan.web [--host H] [--port P]``."""
from __future__ import annotations

import argparse
import sys


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vulnscan-web",
        description="Serve the vulnscan dashboard (local / self-hosted).",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1).")
    parser.add_argument("--port", type=int, default=8088, help="Port (default: 8088).")
    parser.add_argument("--reload", action="store_true", help="Auto-reload on code changes (dev).")
    args = parser.parse_args(argv)

    try:
        import uvicorn
    except ImportError:
        print(
            "The web dashboard needs FastAPI + uvicorn. Install them with:\n"
            "    pip install -r requirements-web.txt",
            file=sys.stderr,
        )
        return 1

    print(f"vulnscan dashboard -> http://{args.host}:{args.port}", file=sys.stderr)
    uvicorn.run("vulnscan.web.app:app", host=args.host, port=args.port, reload=args.reload)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
