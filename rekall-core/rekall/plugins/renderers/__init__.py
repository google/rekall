# Import and register the core plugins
# pylint: disable=unused-import

from rekall.plugins.renderers import base_objects
from rekall.plugins.renderers import darwin
from rekall.plugins.renderers import data_export
from rekall.plugins.renderers import efilter
from rekall.plugins.renderers import json_storage
from rekall.plugins.renderers import linux
from rekall.plugins.renderers import virtualization
from rekall.plugins.renderers import visual_aides
from rekall.plugins.renderers import windows

try:
    from rekall.plugins.renderers import xls
except ImportError:
    pass
