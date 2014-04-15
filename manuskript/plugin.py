import StringIO


class Plugin(object):
    ANGULAR_MODULE = None

    JS_FILES = []
    CSS_FILES = []

    @classmethod
    def PlugIntoApp(cls, app):
        pass

    @classmethod
    def GenerateHTML(cls):
        out = StringIO.StringIO()

        for js_file in cls.JS_FILES:
            out.write("""<script src="%s"></script>\n""" % js_file)

        for css_file in cls.CSS_FILES:
            out.write("""<link rel="stylesheet" href="%s"></link>\n""" %
                      css_file)

        if cls.ANGULAR_MODULE:
            out.write("""
<script>var manuskriptPluginsList = manuskriptPluginsList || [];\n
manuskriptPluginsList.push("%s");</script>\n""" % cls.ANGULAR_MODULE)

        return out.getvalue()
