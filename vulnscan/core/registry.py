"""Runtime discovery of scanner modules (built-ins and user plugins).

Modules are found by importing the configured packages and any extra plugin
directories, then collecting every concrete :class:`ScannerModule` subclass
defined therein. Discovery is resilient: a single import error or a broken
plugin is logged and skipped rather than aborting the whole scan.
"""
from __future__ import annotations

import importlib
import importlib.util
import inspect
import logging
import pkgutil
import sys
from pathlib import Path
from typing import Iterable, Optional

from .module_base import ScannerModule

logger = logging.getLogger("vulnscan.registry")

# Packages scanned by default: the built-in modules and the user plugins package.
DEFAULT_PACKAGES: tuple[str, ...] = ("vulnscan.modules", "vulnscan.plugins")


def _collect_from_module(mod, found: dict, log: logging.Logger, base: type = ScannerModule) -> None:
    for obj in vars(mod).values():
        if (
            inspect.isclass(obj)
            and issubclass(obj, base)
            and obj is not base
            and not inspect.isabstract(obj)
            and obj.__module__ == mod.__name__  # ignore re-imported classes
        ):
            try:
                instance = obj()
            except Exception as exc:  # noqa: BLE001 - never let one bad module break discovery
                log.warning("Could not instantiate module %s: %s", obj.__name__, exc)
                continue
            if not instance.name or instance.name == getattr(base, "name", None):
                log.warning("Skipping module %s: missing a unique 'name'.", obj.__name__)
                continue
            if instance.name in found:
                log.debug("Duplicate module name %r; keeping first.", instance.name)
                continue
            found[instance.name] = instance


def _discover_package(name: str, found: dict, log: logging.Logger, base: type = ScannerModule) -> None:
    try:
        pkg = importlib.import_module(name)
    except ModuleNotFoundError:
        log.debug("Package %s not present; skipping.", name)
        return
    except Exception as exc:  # noqa: BLE001
        log.warning("Failed to import package %s: %s", name, exc)
        return
    if not hasattr(pkg, "__path__"):
        _collect_from_module(pkg, found, log, base)
        return
    for info in pkgutil.iter_modules(pkg.__path__, pkg.__name__ + "."):
        try:
            mod = importlib.import_module(info.name)
        except Exception as exc:  # noqa: BLE001
            log.warning("Skipping module %s (import error): %s", info.name, exc)
            continue
        _collect_from_module(mod, found, log, base)


def _discover_dir(directory: Path, found: dict, log: logging.Logger, base: type = ScannerModule) -> None:
    if not directory.is_dir():
        log.warning("Plugins directory not found: %s", directory)
        return
    for py in sorted(directory.glob("*.py")):
        if py.name.startswith("_"):
            continue
        mod_name = f"_vulnscan_plugin_{py.stem}"
        try:
            spec = importlib.util.spec_from_file_location(mod_name, py)
            if spec is None or spec.loader is None:
                continue
            mod = importlib.util.module_from_spec(spec)
            sys.modules[mod_name] = mod
            spec.loader.exec_module(mod)
        except Exception as exc:  # noqa: BLE001
            log.warning("Skipping plugin file %s (load error): %s", py.name, exc)
            continue
        _collect_from_module(mod, found, log, base)


def discover_modules(
    packages: Iterable[str] = DEFAULT_PACKAGES,
    *,
    extra_dirs: Optional[Iterable[str | Path]] = None,
    log: Optional[logging.Logger] = None,
    base: type = ScannerModule,
) -> list:
    """Return instantiated modules discovered from ``packages`` and ``extra_dirs``.

    ``base`` selects which module family to collect (the network
    :class:`ScannerModule` by default, or ``StaticModule`` for the repo scanner).
    Results are sorted by ``order`` then ``name`` for deterministic execution.
    """
    log = log or logger
    found: dict = {}
    for name in packages:
        _discover_package(name, found, log, base)
    for directory in extra_dirs or ():
        _discover_dir(Path(directory), found, log, base)
    modules = sorted(found.values(), key=lambda m: (m.order, m.name))
    log.debug("Discovered %d modules: %s", len(modules), ", ".join(m.name for m in modules))
    return modules
