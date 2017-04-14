# Import all the renderers.
# pylint: disable=unused-import

from rekall import config
from rekall.ui import renderer
from rekall.ui import json_renderer
from rekall.ui import text
from rekall_lib import utils

config.DeclareOption(
    "-F", "--format", default="text", group="Interface",
    choices=utils.JITIterator(renderer.BaseRenderer),
    help="The output format to use. Default (text)")
