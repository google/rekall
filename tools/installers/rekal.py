"""Main entry point for pyinstaller binaries."""
# Pyinstaller typically can not see these imports.
from rekall import rekal
import rekall.plugins
#import rekall_gui.plugins.webconsole_plugin

rekal.main()
