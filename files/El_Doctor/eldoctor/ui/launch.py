"""GUI launcher used by `eldoctor-gui` and `el_doctor_gui.pyw`.

Imports nothing GUI-related until it has checked that Tk (and a display) exist, so a Python without
tkinter gets a clear instruction instead of a traceback.
"""
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from eldoctor.config import MODES


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="eldoctor-gui", description="El Doctor desktop GUI")
    ap.add_argument("--config", help="config file")
    ap.add_argument("--mode", choices=MODES, help="response mode (overrides config)")
    ap.add_argument("--dry-run", action="store_true", help="never execute destructive actions")
    ap.add_argument("--interval", type=float, help="collection interval in seconds")
    ap.add_argument("--theme", choices=["system", "light", "dark"], help="appearance")
    return ap


def _report(msg: str) -> None:
    """stderr + a dialog when possible (windowed launches on Windows have no console)."""
    print(msg, file=sys.stderr)
    try:
        import tkinter
        from tkinter import messagebox
        r = tkinter.Tk()
        r.withdraw()
        messagebox.showerror("El Doctor", msg)
        r.destroy()
    except Exception:
        pass


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    from eldoctor._bootstrap import missing_dependencies, tk_problem
    missing = missing_dependencies()
    if missing:
        _report("El Doctor is missing Python packages: " + ", ".join(missing) +
                f'\n\nInstall them with:\n"{sys.executable}" -m pip install -r requirements.txt')
        return 1
    from eldoctor._bootstrap import is_frozen, tk_missing
    if tk_missing() and not is_frozen():        # a standalone build never installs or borrows another Python
        from eldoctor.ui.runtime import relaunch_gui
        cli_args = (["--config", args.config] if args.config else []) + ["gui"]
        if args.mode:
            cli_args += ["--mode", args.mode]
        if args.dry_run:
            cli_args.append("--dry-run")
        if args.interval:
            cli_args += ["--interval", str(args.interval)]
        if args.theme:
            cli_args += ["--theme", args.theme]
        rc = relaunch_gui(cli_args)
        if rc is not None:
            return rc
        from eldoctor.ui.runtime import no_tk_help
        _report("The El Doctor desktop GUI needs Tk, which this Python does not have.\n\n" + no_tk_help())
        return 1
    problem = tk_problem()
    if problem:
        _report(f"The El Doctor desktop GUI cannot start: {problem}")
        return 1
    try:
        from eldoctor.config import load_config
        from eldoctor.ui.gui import run_gui
        cfg = load_config(args.config)
        if args.config:
            cfg["_path"] = args.config
        run_gui(cfg, args.mode, args.dry_run, args.interval, theme=args.theme)
    except Exception as exc:
        _report(f"El Doctor could not start:\n\n{type(exc).__name__}: {exc}")
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
