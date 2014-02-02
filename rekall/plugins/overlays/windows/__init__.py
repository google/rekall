# Note that we deliberately do not import all the vtypes here as they get
# imported only when the profile is instantiated. This leads to much faster
# startup times, especially when packed.
# pylint: disable=unused-import

from rekall.plugins.overlays.windows import kernel
from rekall.plugins.overlays.windows import ntfs
from rekall.plugins.overlays.windows import pe_vtypes
from rekall.plugins.overlays.windows import vista
from rekall.plugins.overlays.windows import win7
from rekall.plugins.overlays.windows import win8
from rekall.plugins.overlays.windows import windows
from rekall.plugins.overlays.windows import xp
