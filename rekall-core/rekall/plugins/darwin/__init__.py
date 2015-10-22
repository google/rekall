"""OS X Specific plugins."""
# pylint: disable=unused-import

from rekall.plugins.darwin import address_resolver
from rekall.plugins.darwin import checks
from rekall.plugins.darwin import common
from rekall.plugins.darwin import compressor
from rekall.plugins.darwin import hooks
from rekall.plugins.darwin import lsof
from rekall.plugins.darwin import lsmod
from rekall.plugins.darwin import maps
from rekall.plugins.darwin import misc
from rekall.plugins.darwin import networking
from rekall.plugins.darwin import pas2kas
from rekall.plugins.darwin import processes
from rekall.plugins.darwin import sessions
from rekall.plugins.darwin import sigscan
from rekall.plugins.darwin import zones

# These are optional plugins.
try:
    from rekall.plugins.darwin import yarascan
except (ImportError, OSError):
    pass
