"""Main entry point for pyinstaller binaries."""
# Pyinstaller typically can not see these imports.

# Must be fixed so it can monkey patch fixes for pyinstaller.
import fix_deps

from rekall import rekal
import rekall.plugins
from rekall_agent import agent

rekal.main()
