import os
import sys
from pathlib import Path

# fast password hashing for tests (production default: 600k iterations) - must be set before import
os.environ.setdefault("ELDOCTOR_PBKDF2_ITER", "2000")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("ELDOCTOR_HOME", str(home))
    monkeypatch.setenv("ELDOCTOR_CLIENT_DIR", str(tmp_path / "client"))   # session tokens, GUI prefs
    monkeypatch.delenv("ELDOCTOR_API_KEY", raising=False)
    monkeypatch.delenv("ELDOCTOR_MODE", raising=False)
    monkeypatch.delenv("ELDOCTOR_SOCKET", raising=False)
    return home


@pytest.fixture
def cfg():
    from eldoctor.config import load_config
    c = load_config(overrides={"notifications": {"channels": []}, "logs": {"files": [], "journald": False,
                                                                            "auditd": False,
                                                                            "windows_eventlog": False}})
    # hermetic tests: response actions may only touch processes this test run started
    c["safety"]["only_descendants_of"] = [os.getpid()]
    return c


@pytest.fixture
def store():
    from eldoctor.storage import Store
    s = Store()
    yield s
    s.close()
