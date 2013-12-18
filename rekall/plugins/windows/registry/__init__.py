# Module for memory analysis of the windows registry.
from rekall.plugins.windows.registry import evtlogs
from rekall.plugins.windows.registry import getsids
from rekall.plugins.windows.registry import getservicesids
from rekall.plugins.windows.registry import hivescan

try:
    # This optional plugin requires pycrypto
    from rekall.plugins.windows.registry import lsadump
except ImportError:
    pass

from rekall.plugins.windows.registry import printkey
from rekall.plugins.windows.registry import registry
from rekall.plugins.windows.registry import userassist
