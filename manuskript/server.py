import os
import StringIO

from flask import Flask
from flask import current_app
from flask import helpers

from manuskript import plugins as manuskript_plugins


STATIC_PATH = os.path.join(os.path.dirname(__file__), "static")

DEFAULT_PLUGINS = [manuskript_plugins.PlainText,
                   manuskript_plugins.Markdown,
                   manuskript_plugins.PythonCall]


def RunServer(host="localhost", port=5000, debug=False, plugins=None,
              config=None):
    if not plugins:
        plugins = DEFAULT_PLUGINS

    if not config:
        config = {}

    app = Flask(__name__, static_folder=STATIC_PATH)
    app.config["manuskript_plugins"] = plugins

    # Configure index route
    @app.route("/")
    def index():  # pylint: disable=unused-variable
        plugins_snippets = [p.GenerateHTML()
                            for p in current_app.config['manuskript_plugins']]

        with open(os.path.join(STATIC_PATH, "index.html")) as fd:
            contents = fd.read()
            contents = contents.replace("<!-- manuskript-plugins -->",
                                        "\n".join(plugins_snippets))

        return helpers.send_file(StringIO.StringIO(contents),
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

    app.run(host=host, port=port, debug=debug)
