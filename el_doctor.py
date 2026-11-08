"""Legacy entry point kept for compatibility.

El Doctor 2.x lives in the ``eldoctor`` package.  Running this file starts
the new console (registration + login are required on first use):

    python el_doctor.py             # same as: python -m eldoctor

The original metrics (CPU, memory, disk, network), CSV logging and e-mail
alerts are still there - configured in $ELDOCTOR_HOME/config.yaml instead of
hard-coded credentials in this file.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from eldoctor._bootstrap import ensure_dependencies  # noqa: E402

if __name__ == "__main__":
    ensure_dependencies()
    from eldoctor.cli import main
    raise SystemExit(main())
