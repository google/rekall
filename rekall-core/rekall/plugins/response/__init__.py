# pylint: disable=unused-import
import platform

from rekall.plugins.response import forensic_artifacts
from rekall.plugins.response import common
from rekall.plugins.response import files
from rekall.plugins.response import renderers
from rekall.plugins.response import yara

if platform.system() == "Windows":
    from rekall.plugins.response import registry
    from rekall.plugins.response import windows
