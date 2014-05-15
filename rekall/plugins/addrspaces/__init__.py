# Load the core modules
# pylint: disable=unused-import

from rekall import utils

from rekall.plugins.addrspaces import amd64
from rekall.plugins.addrspaces import crash
# Remove hibernation support as an address space - its too slow to
# actually use. TODO: Convert into a plugin for being able to convert
# from a hibernation file (like imagecopy).
# from rekall.plugins.addrspaces import hibernate
from rekall.plugins.addrspaces import intel
from rekall.plugins.addrspaces import macho
from rekall.plugins.addrspaces import mmap_address_space
from rekall.plugins.addrspaces import standard
from rekall.plugins.addrspaces import vboxelf

utils.ConditionalImport("rekall.plugins.addrspaces.accelerated")
utils.ConditionalImport("rekall.plugins.addrspaces.ewf")

# If we are running on windows, load the windows specific AS.
try:
    import rekall.plugins.addrspaces.win32
except ImportError:
    pass
