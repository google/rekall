# Load the core modules
import sys

from volatility import utils

from volatility.plugins.addrspaces import amd64
from volatility.plugins.addrspaces import crash
from volatility.plugins.addrspaces import hibernate
from volatility.plugins.addrspaces import intel
from volatility.plugins.addrspaces import macho
from volatility.plugins.addrspaces import mmap_address_space
from volatility.plugins.addrspaces import standard
from volatility.plugins.addrspaces import vboxelf

utils.ConditionalImport("volatility.plugins.addrspaces.accelerated")
utils.ConditionalImport("volatility.plugins.addrspaces.ewf")

# If we are running on windows, load the windows specific AS.
utils.ConditionalImport("volatility.plugins.addrspaces.win32")
