import os
import sys
import rekall.compatibility

if getattr(sys, "frozen", None):
    # Pyinstaller package.
    RESOURCES_PATH = os.path.dirname(sys.executable)
else:
    RESOURCES_PATH = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "resources")

from ._version import get_versions
__version__ = get_versions()['version']
