# Import and register the core plugins
from volatility.plugins import addrspaces
#from volatility.plugins import bioskbd
from volatility.plugins import core

# This plugin is not really important.
# from volatility.plugins import imagecopy

# This will be removed in favor of profile autodetection + kdbg scan.
# from volatility.plugins import imageinfo
from volatility.plugins import linux
from volatility.plugins import overlays

# This will be deprecated in favor of the new pfn plugins which are much faster.
from volatility.plugins import windows
