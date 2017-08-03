"""Main entry point for pyinstaller binaries."""
# Pyinstaller typically can not see these imports.
from rekall import rekal
import rekall.plugins
from rekall_agent import agent
#import rekall_gui.plugins.webconsole_plugin

rekal.main()
