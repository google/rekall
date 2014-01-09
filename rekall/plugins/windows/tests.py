# pylint: disable=unused-import

from rekall.plugins.windows import connections_test
from rekall.plugins.windows import connscan_test
from rekall.plugins.windows import filescan_test
from rekall.plugins.windows import handles_test
from rekall.plugins.windows import kdbgscan_test
from rekall.plugins.windows import pfn_test
from rekall.plugins.windows import procdump_test
from rekall.plugins.windows import modules_test
from rekall.plugins.windows import taskmods_test
from rekall.plugins.windows import vadinfo_test

# The registry module tests.
from rekall.plugins.windows.gui import tests
from rekall.plugins.windows.registry import tests
from rekall.plugins.windows.malware import tests
