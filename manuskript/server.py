import os
import StringIO

from flask import Flask
from flask import helpers

from manuskript import plugins as manuskript_plugins

from werkzeug import serving


STATIC_PATH = os.path.join(os.path.dirname(__file__), "static")

DEFAULT_PLUGINS = [manuskript_plugins.PlainText,
                   manuskript_plugins.Markdown,
                   manuskript_plugins.PythonCall]


class WebconsoleWSGIServer(serving.BaseWSGIServer):
    """Custom WSGI server that supports post-activate hook."""

    def __init__(self, host, port, app, post_activate_callback=None):
        self.post_activate_callback = post_activate_callback
        super(WebconsoleWSGIServer, self).__init__(host, port, app)

    def server_activate(self):
        super(WebconsoleWSGIServer, self).server_activate()
        if self.post_activate_callback:
            self.post_activate_callback(self)


def ExpandManuskriptHeaders(plugins, root_url="/", **opts):
    """Generate the headers to go into the manuskript <head> tag."""
    app = manuskript_plugins.MainApp
    app.CONFIG.update(opts)

    components = [manuskript_plugins.AppDeps] + plugins + [app]

    header = "\n".join([p.GenerateHTML() for p in components])

    with open(os.path.join(STATIC_PATH, "index.html")) as fd:
        contents = fd.read() % dict(root_url=root_url)
        contents = contents.replace(
            "<!-- manuskript-headers -->", header)

        return contents

def InitializeApp(plugins=None, config=None):
    if not plugins:
        plugins = DEFAULT_PLUGINS

    if not config:
        config = {}

    app = Flask(__name__, static_folder=STATIC_PATH)

    # Configure index route
    @app.route("/")
    def index():  # pylint: disable=unused-variable
        return helpers.send_file(
            StringIO.StringIO(ExpandManuskriptHeaders(plugins)),
            mimetype="text/html",
            conditional=True)

    # Turn off caching for easier development/debugging
    @app.after_request
    def add_header(response):  # pylint: disable=unused-variable
        """Turn off caching for easier debugging."""
        response.headers['Cache-Control'] = 'no-cache, no-store'
        return response

    for plugin_cls in plugins:
        plugin_cls.PlugIntoApp(app)

    for k, v in config.items():
        app.config[k] = v

    return app

def RunServer(host="localhost", port=0, debug=False, plugins=None,
              config=None, post_activate_callback=None):
    # Port number 0 will cause the system to bind a random port.
    app = InitializeApp(plugins=plugins, config=config)

    if debug:
        app.run(host=host, port=port, debug=debug)
    else:
        WebconsoleWSGIServer(
            host, port, app,
            post_activate_callback=post_activate_callback).serve_forever()
