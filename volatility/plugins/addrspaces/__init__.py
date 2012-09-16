# Load the core modules
import sys

from volatility.plugins.addrspaces import amd64
from volatility.plugins.addrspaces import crash
#from volatility.plugins.addrspaces import ewf
from volatility.plugins.addrspaces import hibernate
#from volatility.plugins.addrspaces import ieee1394
from volatility.plugins.addrspaces import intel
from volatility.plugins.addrspaces import macho
from volatility.plugins.addrspaces import mmap_address_space
from volatility.plugins.addrspaces import standard
from volatility.plugins.addrspaces import vboxelf

# If we are running on windows, load the windows specific AS.
if sys.platform == "win32":
    from volatility.plugins.addrspaces import win32
