"""Entry point for `python -m eldoctor`, `python eldoctor` and `python eldoctor/__main__.py`."""
import os
import sys

if not __package__:  # run as a script / folder, not with -m: make `import eldoctor` work
    _pkg = os.path.dirname(os.path.abspath(__file__))
    sys.path[:] = [p for p in sys.path if os.path.abspath(p or os.curdir) != _pkg]
    sys.path.insert(0, os.path.dirname(_pkg))

from eldoctor._bootstrap import ensure_dependencies  # noqa: E402

ensure_dependencies()

from eldoctor.cli import main  # noqa: E402

if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
