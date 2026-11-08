"""Entry point of the windowed "El Doctor.exe" (Windows): the desktop GUI without a console window."""
import sys

from eldoctor.ui.launch import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
