# Import all the renderers.
# pylint: disable=unused-import

from rekall import config
from rekall.ui import renderer
from rekall.ui import json_renderer
from rekall.ui import text

class JITIterator(object):
    def __contains__(self, item):
        return item in list(self)

    def __iter__(self):
        return (
            x.name for x in renderer.BaseRenderer.classes.values() if x.name)


config.DeclareOption(
    "-r", "--renderer", default="text", group="Interface",
    choices=JITIterator(), help="The renderer to use. Default (text)")

