# Import and register the core plugins
# pylint: disable=unused-import

from rekall.plugins.renderers import data_export
from rekall.plugins.renderers import json_storage

try:
    from rekall.plugins.renderers import xls
except ImportError:
    pass

from rekall.plugins.renderers import windows
from rekall.plugins.renderers import virtualization
