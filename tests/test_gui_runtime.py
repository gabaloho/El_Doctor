"""GUI runtime auto-provisioning: the GUI must work from a Python that has no tkinter (no sudo needed)."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

from eldoctor.ui import runtime

ROOT = Path(__file__).resolve().parents[1]


def test_probe_rejects_interpreter_without_tk(tmp_path):
    fake = tmp_path / "python-no-tk"
    fake.write_text("#!/bin/sh\necho 'ModuleNotFoundError: No module named tkinter' >&2\nexit 1\n")
    fake.chmod(0o755)
    assert runtime.probe(str(fake)) is None
    assert runtime.probe("/nonexistent/python") is None


def test_candidates_exclude_current_interpreter_and_dedupe():
    c = runtime.candidates()
    reals = [os.path.realpath(p) for p in c]
    assert os.path.realpath(sys.executable) not in reals
    assert len(reals) == len(set(reals))


def test_forced_interpreter_is_tried_first(monkeypatch, tmp_path):
    fake = tmp_path / "mypython"
    fake.write_text("#!/bin/sh\nexit 1\n")
    fake.chmod(0o755)
    monkeypatch.setenv("ELDOCTOR_GUI_PYTHON", str(fake))
    assert runtime.candidates()[0] == str(fake)


def test_no_loop_when_already_inside_runtime(monkeypatch):
    monkeypatch.setenv("ELDOCTOR_GUI_RUNTIME", "/x/python")
    assert runtime.relaunch_gui(["gui"], log=lambda m: None) is None


def test_helpful_message_when_no_tk_python(monkeypatch):
    msgs = []
    monkeypatch.delenv("ELDOCTOR_GUI_RUNTIME", raising=False)
    monkeypatch.setattr(runtime, "ready_runtime", lambda: None)      # no runtime built earlier
    monkeypatch.setattr(runtime, "find_tk_python", lambda log=print: None)
    monkeypatch.setattr(runtime, "uv_install", lambda log=print: None)
    assert runtime.relaunch_gui(["gui"], log=msgs.append) is None
    text = "\n".join(msgs)
    assert "uv python install" in text and "sudo" in text and "eldoctor tui" in text


def test_cli_gui_uses_runtime_when_tk_missing(monkeypatch):
    from eldoctor import _bootstrap, cli
    from eldoctor.ui import runtime as rt
    calls = []
    monkeypatch.setattr(_bootstrap, "tk_missing", lambda: True)
    monkeypatch.setattr(rt, "relaunch_gui", lambda argv, log=print: calls.append(argv) or 0)
    assert cli.main(["gui", "--mode", "monitor"]) == 0
    assert calls == [["gui", "--mode", "monitor"]]


def test_launcher_maps_options_for_runtime(monkeypatch):
    from eldoctor import _bootstrap
    from eldoctor.ui import launch, runtime as rt
    calls = []
    monkeypatch.setattr(_bootstrap, "tk_missing", lambda: True)
    monkeypatch.setattr(rt, "relaunch_gui", lambda argv, log=print: calls.append(argv) or 0)
    assert launch.main(["--config", "c.yaml", "--mode", "enforce", "--dry-run"]) == 0
    assert calls == [["--config", "c.yaml", "gui", "--mode", "enforce", "--dry-run"]]


@pytest.mark.skipif(runtime.find_tk_python(lambda m: None) is None, reason="no Tk-capable Python on this machine")
def test_end_to_end_runtime_runs_this_source_tree():
    """Real run: provision (or reuse) the runtime and execute `python -m eldoctor --version` inside it."""
    code = ("import sys; from eldoctor.ui import runtime; "
            "sys.exit(runtime.relaunch_gui(['--version'], log=lambda m: None) or 0)")
    env = {k: v for k, v in os.environ.items() if k != "ELDOCTOR_GUI_RUNTIME"}
    r = subprocess.run([sys.executable, "-c", code], cwd=str(ROOT), capture_output=True, text=True, timeout=600,
                       env=env)
    assert r.returncode == 0, r.stderr
    assert "El Doctor 2." in r.stdout


def test_fast_path_reuses_built_runtime(monkeypatch, tmp_path):
    """Second start: a ready runtime is used directly - no search across all interpreters."""
    calls = []
    monkeypatch.delenv("ELDOCTOR_GUI_RUNTIME", raising=False)
    monkeypatch.setattr(runtime, "ready_runtime", lambda: (tmp_path / "python", "3.14.7"))
    monkeypatch.setattr(runtime, "find_tk_python", lambda log=print: calls.append("search"))
    monkeypatch.setattr(runtime, "_run", lambda vpy, ver, argv, log: calls.append(("run", ver, argv)) or 0)
    assert runtime.relaunch_gui(["gui"], log=lambda m: None) == 0
    assert calls == [("run", "3.14.7", ["gui"])]


def test_ready_runtime_ignored_when_interpreter_forced(monkeypatch):
    monkeypatch.setenv("ELDOCTOR_GUI_PYTHON", "/some/python")
    assert runtime.ready_runtime() is None
