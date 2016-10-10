
from rekall.ui import text


class UILink(object):
    def __init__(self, action, link):
        self.action = action
        self.link = link

class UILinkObjectTextRenderer(text.TextObjectRenderer):
    renders_type = "UILink"

    def render_full(self, target, **_):
        return text.Cell(u"%s:%s" % (target.action, target.link))

    def render_compact(self, target, **_):
        return text.Cell(target.link)
