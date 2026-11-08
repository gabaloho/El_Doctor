"""Double-click launcher for the El Doctor desktop GUI (Windows opens .pyw files without a console window).

Equivalent to:  python eldoctor gui
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    from eldoctor.ui.launch import main
    raise SystemExit(main(sys.argv[1:]))
