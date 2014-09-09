# Import all the renderers.
# pylint: disable=unused-import

from rekall import config
from rekall import utils
from rekall.ui import renderer
from rekall.ui import json_renderer
from rekall.ui import text

config.DeclareOption(
    "-r", "--renderer", default="text", group="Interface",
    choices=utils.JITIterator(renderer.BaseRenderer),
    help="The renderer to use. Default (text)")

