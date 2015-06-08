# Module for memory analysis of the windows registry.
# pylint: disable=unused-import
from rekall.plugins.windows.registry import evtlogs
from rekall.plugins.windows.registry import getsids
from rekall.plugins.windows.registry import getservicesids

# Disabled currently since it only works on XP and it also appears to be broken.
#try:
    # This optional plugin requires pycrypto
#    from rekall.plugins.windows.registry import lsadump
#except ImportError:
#    pass

from rekall.plugins.windows.registry import printkey
from rekall.plugins.windows.registry import registry
from rekall.plugins.windows.registry import userassist
