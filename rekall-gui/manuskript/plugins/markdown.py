from manuskript import plugin


class Markdown(plugin.Plugin):
    ANGULAR_MODULE = "manuskript.markdown"

    JS_FILES = ["/static/components/markdown/markdown-controller.js",
                "/static/components/markdown/markdown.js"]
