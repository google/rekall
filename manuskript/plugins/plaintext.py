from manuskript import plugin


class PlainText(plugin.Plugin):
    ANGULAR_MODULE = "manuskript.plaintext"

    JS_FILES = ["/static/components/plaintext/plaintext-controller.js",
                "/static/components/plaintext/plaintext.js"]
    CSS_FILES = ["/static/components/plaintext/plaintext.css"]
