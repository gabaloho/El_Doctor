"""Entry point of the standalone `eldoctor` executable (console): every CLI command, TUI, GUI, service."""
import sys

from eldoctor.cli import main

if __name__ == "__main__":
    sys.exit(main())
