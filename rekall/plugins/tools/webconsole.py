#!/usr/bin/env python2

# Rekall Memory Forensics
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Author: Michael Cohen scudette@google.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

__author__ = "Mikhail Bushkov <mbushkov@google.com>"

import argparse
import sys
import os
import StringIO
import sys

from rekall import config
from rekall import plugin
from rekall import testlib

from flask import Blueprint
from flask import jsonify
from flask import request

from manuskript import server as manuskript_server
from manuskript import plugin as manuskript_plugin
from manuskript import plugins as manuskript_plugins

try:
    STATIC_PATH = os.path.join(sys._MEIPASS, "webconsole") # pylint: disable=protected-access
except AttributeError:
    STATIC_PATH = os.path.join(os.path.dirname(__file__), "webconsole")

class RekallPythonCall(manuskript_plugins.PythonCall):
    """PythonCall extension that inserts Rekall session into local context."""

    @classmethod
    def UpdatePythonShell(cls, app, shell):
        super(RekallPythonCall, cls).UpdatePythonShell(app, shell)

        rekall_session = app.config["rekall_session"]
        shell.local_context = rekall_session._locals # pylint: disable=protected-access


class FakeParser(object):
    """Fake parser used to reflect on plugins' arguments."""

    def __init__(self):
        self.arguments = []

    def add_argument(self, name, *unused_args, **kwargs):
        # Remove starting dashes.
        while name.startswith("-"):
            name = name[1:]

        argument_def = {}
        argument_def["name"] = name

        argument_def["required"] = kwargs.get("required", False)

        if "help" in kwargs:
            argument_def["help"] = kwargs["help"]

        if "nargs" in kwargs:
            argument_def["nargs"] = kwargs["nargs"]

        if "choices" in kwargs:
            if hasattr(kwargs["choices"], "keys"):
                argument_def["choices"] = kwargs["choices"].keys()
            else:
                argument_def["choices"] = list(kwargs["choices"])

        passed_default = kwargs.get("default", None)
        if (passed_default is None and
            "choices" in argument_def and argument_def["choices"]):
            passed_default = argument_def["choices"][0]

        arg_type = "string"

        # Try to guess argument type by the type of a default value.
        if passed_default:
            argument_def["default"] = passed_default
            if isinstance(passed_default, bool):
                arg_type = "bool"
            elif isinstance(passed_default, int):
                arg_type = "int"
        # If we can't guess by default value, inspect parser's action.
        elif "action" in kwargs:
            action = kwargs["action"]
            if action is config.IntParser:
                arg_type = "int"
            elif action is config.ArrayIntParser:
                arg_type = "int"
            elif action == "store_true":
                arg_type = "bool"

        argument_def["type"] = arg_type
        self.arguments.append(argument_def)


class RekallWebConsole(manuskript_plugin.Plugin):

    ANGULAR_MODULE = "rekall.webconsole"

    JS_FILES = [
        "/rekall-webconsole/pluginregistry-service.js",
        "/rekall-webconsole/pluginarguments-directive.js",
        "/rekall-webconsole/runplugin-controller.js",
        "/rekall-webconsole/runplugin.js",
        "/rekall-webconsole/webconsole.js"
        ]

    @classmethod
    def PlugIntoApp(cls, app):
        super(RekallWebConsole, cls).PlugIntoApp(app)

        # Use blueprint as an easy way to serve static files.
        bp = Blueprint('rekall-webconsole', __name__,
                       static_url_path="/rekall-webconsole",
                       static_folder=STATIC_PATH)
        @bp.after_request
        def add_header(response):  # pylint: disable=unused-variable
            response.headers['Cache-Control'] = 'no-cache, no-store'
            return response
        app.register_blueprint(bp)

        @app.route("/rekall/plugins/all")
        def list_all_plugins():   # pylint: disable=unused-variable
            session = app.config['rekall_session']
            plugins = plugin.Command.GetActiveClasses(session)

            result = {}
            for plugin_cls in plugins:
                plugin_def = {}

                plugin_def["name"] = getattr(plugin_cls, "name", None)

                if not plugin_def["name"]:
                    continue

                plugin_def["description"] = plugin_cls.__doc__

                parser = FakeParser()
                plugin_cls.args(parser)
                plugin_def["arguments"] = parser.arguments

                result[plugin_def["name"]] = plugin_def

            return jsonify({"data": result})

        @app.route("/rekall/runplugin", methods=["POST"])
        def run_plugin():   # pylint: disable=unused-variable
            rekall_session = app.config["rekall_session"]
            source = request.get_json()["source"]

            stdout = StringIO.StringIO()
            stderr = StringIO.StringIO()
            prev_stdout = sys.stdout
            prev_stderr = sys.stderr
            sys.stdout = stdout
            sys.stderr = stderr

            try:
                plugin_cls = plugin.Command.classes_by_name[
                    source["plugin"]["name"]]

                cmdline_args = []
                for arg_key, arg_value in source["arguments"].iteritems():
                    if arg_value == "":
                        continue
                    cmdline_args.extend(["--" + arg_key, arg_value])

                parser = argparse.ArgumentParser()
                plugin_cls.args(parser)
                kwargs = vars(parser.parse_args(cmdline_args))

                rekall_session.RunPlugin(source["plugin"]["name"], **kwargs)
            finally:
                sys.stdout = prev_stdout
                sys.stderr = prev_stderr

            stdout_lines = (stdout.getvalue() and
                            stdout.getvalue().split("\n") or [])
            stderr_lines = (stderr.getvalue() and
                            stderr.getvalue().split("\n") or [])

            response = jsonify(data=dict(stdout=stdout_lines,
                                         stderr=stderr_lines))
            return response


class WebConsole(plugin.Command):
    """Launch the web-based console notebook."""

    __name = "webconsole"

    @classmethod
    def args(cls, parser):
        super(WebConsole, cls).args(parser)

        parser.add_argument("--host", default="localhost",
                            help="Host for the web console to use.")

        parser.add_argument("--port", default=5000,
                            help="Port for the web console to use.")

        parser.add_argument("--debug", default=False,
                            help="Start in the debug mode (will monitor "
                            "changes in the resources and reload them as "
                            "needed.")

    def __init__(self, host="localhost", port=5000, debug=False, **kwargs):
        super(WebConsole, self).__init__(**kwargs)
        self.host = host
        self.port = port
        self.debug = debug

    def render(self, renderer):
        renderer.format("Starting Manuskript web console.")
        renderer.format("Press Ctrl-c to return to the interactive shell.")
        manuskript_server.RunServer(
            host=self.host, port=self.port, debug=self.debug,
            plugins=[manuskript_plugins.PlainText,
                     manuskript_plugins.Markdown,
                     RekallWebConsole, RekallPythonCall],
            config=dict(rekall_session=self.session))


class TestWebConsole(testlib.DisabledTest):
    """Disable the test for this command to avoid bringing up the notebook."""
    PARAMETERS = dict(commandline="webconsole")
