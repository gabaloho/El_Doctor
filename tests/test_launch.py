"""Regression tests: every documented way of starting El Doctor must work (bug: `python eldoctor` failed
with '<frozen runpy>' ... ModuleNotFoundError), and missing dependencies give instructions, not tracebacks."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("args,cwd", [
    (["eldoctor"], ROOT),                         # python eldoctor   (run the folder)
    (["-m", "eldoctor"], ROOT),                   # python -m eldoctor
    (["el_doctor.py"], ROOT),                     # legacy script
    (["eldoctor/__main__.py"], ROOT),
    (["eldoctor/cli.py"], ROOT),
    ([str(ROOT / "eldoctor")], ROOT.parent),      # from another directory
    ([str(ROOT / "el_doctor.py")], Path("/")),
])
def test_launch_styles(args, cwd):
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    r = subprocess.run([sys.executable, *args, "--version"], cwd=str(cwd), capture_output=True, text=True,
                       env=env, timeout=60)
    assert r.returncode == 0, r.stderr
    assert "El Doctor 2." in r.stdout
    assert "Traceback" not in r.stderr


def test_hint_uses_the_invocation():
    r = subprocess.run([sys.executable, "eldoctor", "alerts"], cwd=str(ROOT), capture_output=True, text=True,
                       timeout=60)
    assert r.returncode == 2 and "eldoctor register" in r.stderr and "Traceback" not in r.stderr


def test_missing_dependency_message(monkeypatch, capsys):
    from eldoctor import _bootstrap
    monkeypatch.setitem(_bootstrap.REQUIRED, "surely_not_installed_mod", "surely-not-installed>=1")
    with pytest.raises(SystemExit) as exc:
        _bootstrap.ensure_dependencies()
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "surely-not-installed" in err and "-m pip install" in err and sys.executable in err


def test_tui_falls_back_without_curses(monkeypatch, capsys):
    """Windows without windows-curses: the console must fall back to text mode instead of crashing."""
    from eldoctor import _bootstrap, cli
    monkeypatch.setattr(_bootstrap, "curses_available", lambda: False)

    class Stop(Exception):
        pass

    def fake_run(args):
        assert args.headless is True
        raise Stop
    monkeypatch.setattr(cli, "cmd_run", fake_run)
    ns = cli.build_parser().parse_args(["tui"])
    with pytest.raises(Stop):
        cli.cmd_tui(ns)
    assert "text console" in capsys.readouterr().out and ns.headless is True


@pytest.mark.parametrize("args", [["eldoctor", "gui", "--help"], ["el_doctor_gui.pyw", "--help"]])
def test_gui_entry_points(args):
    r = subprocess.run([sys.executable, *args], cwd=str(ROOT), capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and "--mode" in r.stdout and "Traceback" not in r.stderr


def test_gui_reports_missing_tk_or_display(monkeypatch, capsys):
    from eldoctor import _bootstrap, cli
    monkeypatch.setattr(_bootstrap, "tk_missing", lambda: False)
    monkeypatch.setattr(_bootstrap, "tk_problem", lambda: "No graphical display (DISPLAY is not set).")
    assert cli.main(["gui"]) == 1
    assert "DISPLAY" in capsys.readouterr().err


def test_no_auto_runtime_flag(monkeypatch, capsys):
    from eldoctor import _bootstrap, cli
    monkeypatch.setattr(_bootstrap, "tk_missing", lambda: True)
    monkeypatch.setattr(_bootstrap, "tk_problem", lambda: "Tkinter is missing.")
    assert cli.main(["gui", "--no-auto-runtime"]) == 1
    assert "Tkinter is missing" in capsys.readouterr().err
