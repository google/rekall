import StringIO


class Plugin(object):
    ANGULAR_MODULE = None

    JS_FILES = []
    CSS_FILES = []

    @classmethod
    def PlugIntoApp(cls, app):
        pass

    @classmethod
    def GenerateHTML(cls, root_url="/"):
        out = StringIO.StringIO()
        for js_file in cls.JS_FILES:
            js_file = js_file.lstrip("/")
            out.write('<script src="%s%s"></script>\n' % (root_url, js_file))

        for css_file in cls.CSS_FILES:
            css_file = css_file.lstrip("/")
            out.write('<link rel="stylesheet" href="%s%s"></link>\n' % (
                root_url, css_file))

        if cls.ANGULAR_MODULE:
            out.write("""
<script>var manuskriptPluginsList = manuskriptPluginsList || [];\n
manuskriptPluginsList.push("%s");</script>\n""" % cls.ANGULAR_MODULE)

        return out.getvalue()
