import os
import sys
import rekall.compatibility

RESOURCES_PATH = []
if __file__:
    # PIP packages.
    RESOURCES_PATH.append(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "resources"))

if getattr(sys, "frozen", None):
    # Pyinstaller package.
    RESOURCES_PATH.append(os.path.dirname(sys.executable))

def get_resource(name):
    for path in RESOURCES_PATH:
        full_path = os.path.join(path, "./", name)
        if os.access(full_path, os.R_OK):
            return full_path


from ._version import get_versions
__version__ = get_versions()['version']
