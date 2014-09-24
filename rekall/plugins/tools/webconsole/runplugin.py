#!/usr/bin/env python2

# Rekall Memory Forensics
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Author: Mikhail Bushkov realbushman@gmail.com
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

__author__ = "Mikhail Bushkov <realbushman@gmail.com>"


import argparse
import logging
import StringIO
import traceback

from flask import jsonify
from flask import json

from rekall.plugins.renderers import data_export
from rekall import config
from rekall import plugin

from flask_sockets import Sockets

from manuskript import plugin as manuskript_plugin


class FakeParser(object):
    """Fake parser used to reflect on Replugins' arguments."""

    def __init__(self):
        self.arguments = []

    def add_argument(self, name, *unused_args, **kwargs):
        positional = not name.startswith("-")

        # Remove starting dashes.
        while name.startswith("-"):
            name = name[1:]

        argument_def = {}
        argument_def["name"] = name
        argument_def["positional"] = positional

        argument_def["required"] = positional or kwargs.get("required", False)

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


class WebConsoleRenderer(data_export.DataExportRenderer):
    # This renderer is private to the web console.
    name = None

    spinner = r"/-\|"
    last_spin = 0

    def __init__(self, ws=None, **kwargs):
        super(WebConsoleRenderer, self).__init__(**kwargs)
        self.ws = ws
        self.queue = []

    def SendMessage(self, message):
        self.ws.send(json.dumps([message]))
        self.queue.append(message)

    def RenderProgress(self, message=" %(spinner)s", *args, **kwargs):
        if "%(" in message:
            self.last_spin += 1
            kwargs["spinner"] = self.spinner[
                self.last_spin % len(self.spinner)]

            formatted_message = message % kwargs
        elif args:
            format_args = []
            for arg in args:
                if callable(arg):
                    format_args.append(arg())
                else:
                    format_args.append(arg)

            formatted_message = message % tuple(format_args)
        else:
            formatted_message = message

        self.SendMessage(["p", formatted_message])


class WebConsoleObjectRenderer(data_export.NativeDataExportObjectRenderer):
    renders_type = "object"
    renderers = ["WebConsoleRenderer"]

    def _GetDelegateObjectRenderer(self, item):
        return self.FromEncoded(item, "DataExportRenderer")(
            renderer=self.renderer)

    def EncodeToJsonSafe(self, item, **options):
        return self._GetDelegateObjectRenderer(item).EncodeToJsonSafe(
            item, **options)

    def DecodeFromJsonSafe(self, value, options):
        return self._GetDelegateObjectRenderer(value).DecodeFromJsonSafe(
            value, options)


class RekallRunPlugin(manuskript_plugin.Plugin):

    ANGULAR_MODULE = "rekall.runplugin"

    JS_FILES = [
        "/rekall-webconsole/components/runplugin/contextmenu-directive.js",
        "/rekall-webconsole/components/runplugin/freeformat-directive.js",
        "/rekall-webconsole/components/runplugin/jsondecoder-service.js",
        "/rekall-webconsole/components/runplugin/objectactions-init.js",
        "/rekall-webconsole/components/runplugin/objectactions-service.js",
        "/rekall-webconsole/components/runplugin/objectrenderer-directive.js",
        "/rekall-webconsole/components/runplugin/pluginarguments-directive.js",
        "/rekall-webconsole/components/runplugin/pluginregistry-service.js",
        "/rekall-webconsole/components/runplugin/runplugin-controller.js",
        "/rekall-webconsole/components/runplugin/scroll-table-directive.js",

        "/rekall-webconsole/components/runplugin/runplugin.js",
        ]

    CSS_FILES = [
        "/rekall-webconsole/components/runplugin/runplugin.css",
        ]

    @classmethod
    def PlugListPluginsIntoApp(cls, app):

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

    @classmethod
    def PlugManageDocument(cls, app):
        sockets = Sockets(app)

        @sockets.route("/rekall/document/upload")
        def upload_document(ws):  # pylint: disable=unused-variable
            cells = json.loads(ws.receive())
            worksheet = app.config['worksheet']
            if cells:
                worksheet.StoreData("notebook_cells", cells)

        @sockets.route("/rekall/load_nodes")
        def rekall_load_nodes(ws):  # pylint: disable=unused-variable
            worksheet = app.config["worksheet"]
            cells = worksheet.GetData("notebook_cells") or []
            print "load_nodes", cells

            ws.send(json.dumps(cells))

    @classmethod
    def PlugRunPluginsIntoApp(cls, app):
        sockets = Sockets(app)

        @sockets.route("/rekall/runplugin")
        def rekall_run_plugin_socket(ws):  # pylint: disable=unused-variable
            source = json.loads(ws.receive())
            plugin_data = source["plugin"]
            plugin_name = plugin_data["name"]
            cookie = source.get("cookie")
            rekall_session = app.config["rekall_session"]
            worksheet = app.config["worksheet"]

            # If the data is cached locally just return it.
            cache_key = "%s_%s" % (plugin_name, cookie)
            cache = worksheet.GetData(cache_key)
            if cache:
                logging.debug("Dumping request from cache")
                ws.send(json.dumps(cache))
                return

            plugin_cls = plugin.Command.classes_by_name[plugin_name]

            fake_parser = FakeParser()
            plugin_cls.args(fake_parser)

            cmdline_args = []
            keyword_args = {}
            for arg in fake_parser.arguments:
                if arg["positional"]:
                    cmdline_args.append(source["arguments"][arg["name"]])
                else:
                    arg_value = source["arguments"].get(arg["name"], "")
                    if arg_value == "":
                        continue
                    keyword_args[arg["name"]] = arg_value

            for arg_name, arg_value in keyword_args.iteritems():
                cmdline_args.extend(["--" + arg_name, arg_value])

            parser = argparse.ArgumentParser()
            plugin_cls.args(parser)
            kwargs = vars(parser.parse_args(cmdline_args))

            output = StringIO.StringIO()
            renderer = WebConsoleRenderer(
                session=rekall_session, output=output,
                ws=ws)

            with renderer.start():
                try:
                    rekall_session.RunPlugin(source["plugin"]["name"],
                                             renderer=renderer,
                                             **kwargs)
                except Exception:
                    message = traceback.format_exc()
                    renderer.report_error(message)

            # Cache the data in the worksheet.
            cache_key = "%s_%s" % (plugin_name, renderer._object_id)
            worksheet.StoreData(cache_key, renderer.queue)

    @classmethod
    def PlugIntoApp(cls, app):
        super(RekallRunPlugin, cls).PlugIntoApp(app)

        cls.PlugListPluginsIntoApp(app)
        cls.PlugRunPluginsIntoApp(app)
        cls.PlugManageDocument(app)
