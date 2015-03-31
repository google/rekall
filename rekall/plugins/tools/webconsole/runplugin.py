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


import cStringIO
import hashlib
import logging
import os
import Queue
import stat
import traceback
import zipfile

from flask import jsonify
from flask import json
from flask import request

import gevent
from gevent import threadpool

from rekall.plugins.renderers import data_export
from rekall import config
from rekall import io_manager
from rekall import plugin
from rekall import utils
from rekall.ui import json_renderer

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

    def __init__(self, output_queue=None, worksheet=None, cell_id=0, **kwargs):
        """Initialize a WebConsoleRenderer.

        Args:
          ws: A websocket we use to stream messages over.
          worksheet: The worksheet file to store files.
          cell_id: The cell id we are running under.
        """
        super(WebConsoleRenderer, self).__init__(**kwargs)
        self.output_queue = output_queue
        self.cell_id = cell_id
        self.worksheet = worksheet

    def SendMessage(self, message):
        self.output_queue.put(message)

    def open(self, directory=None, filename=None, mode="rb"):
        if filename is None and directory is None:
            raise IOError("Must provide a filename")

        if directory:
            filename = os.path.normpath(os.path.join(directory, "./", filename))

        # Store files under this cell_id This prevents this cell's files from
        # being mixed with other cell's files.
        full_path = "%s/%s" % (self.cell_id, filename)

        # Export the fact that we wrote a file using the special "f" command.
        self.SendMessage(["file", filename, full_path])

        if 'w' in mode:
            return self.worksheet.Create(full_path)

        return self.worksheet.Open(full_path)

    def RenderProgress(self, *args, **kwargs):
        if self.cell_id in self.worksheet.aborted_cells:
            self.worksheet.aborted_cells.discard(self.cell_id)
            raise plugin.Abort()

        return super(WebConsoleRenderer, self).RenderProgress(*args, **kwargs)


def GenerateCacheKey(state):
    data = json.dumps(state, sort_keys=True)
    hash = hashlib.md5(data).hexdigest()
    try:
        return "%s-%s" % (hash, state["plugin"]["name"])
    except KeyError:
        return hash


class WebConsoleObjectRenderer(data_export.NativeDataExportObjectRenderer):
    renders_type = "object"
    renderers = ["WebConsoleRenderer"]

    def _GetDelegateObjectRenderer(self, item):
        return self.FromEncoded(item, "DataExportRenderer")(
            renderer=self.renderer)

    def EncodeToJsonSafe(self, item, **options):
        object_renderer = self.ForTarget(item, "DataExportRenderer")
        return object_renderer(renderer=self.renderer).EncodeToJsonSafe(
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
        "/rekall-webconsole/components/runplugin/paged-table-directive.js",
        "/rekall-webconsole/components/runplugin/pluginarguments-directive.js",
        "/rekall-webconsole/components/runplugin/pluginregistry-service.js",
        "/rekall-webconsole/components/runplugin/runplugin-controller.js",
        "/rekall-webconsole/components/runplugin/scroll-table-directive.js",
        "/rekall-webconsole/components/runplugin/runplugin.js",

        # Session management.
        "/rekall-webconsole/components/sessions/session-arguments-directive.js",
        "/rekall-webconsole/components/sessions/manage-sessions-controller.js",

        # File upload directives
        "/rekall-webconsole/components/fileupload/fileupload.js",
        "/rekall-webconsole/components/fileupload/fileupload-controller.js",

        ]

    CSS_FILES = [
        "/rekall-webconsole/components/runplugin/runplugin.css",
        "/rekall-webconsole/components/fileupload/fileupload.css",
        "/rekall-webconsole/components/sessions/manage-sessions.css",
        ]

    @classmethod
    def PlugListPluginsIntoApp(cls, app):

        @app.route("/rekall/plugins/all/<session_id>")
        def list_all_plugins(session_id):  # pylint: disable=unused-variable
            worksheet = app.config["worksheet"]
            session = worksheet.session.find_session(int(session_id))
            return jsonify(session.plugins.plugin_db.Serialize())

        @app.route("/rekall/symbol_search")
        def search_symbol():  # pylint: disable=unused-variable
            symbol = request.args.get("symbol", "")
            session_id = int(request.args["session_id"])

            results = []
            if len(symbol) >= 3:
                try:
                    rekall_session = app.config[
                        "worksheet"].session.find_session(session_id)

                    results = sorted(
                        rekall_session.address_resolver.search_symbol(
                            symbol+"*"))

                    results = results[:10]
                except RuntimeError:
                    pass

            return jsonify(dict(results=results))

    @classmethod
    def SessionManager(cls, app):

        @app.route("/sessions/update", methods=["POST"])
        def update_sessions():  # pylint: disable=unused-variable
            worksheet = app.config['worksheet']
            sessions = request.get_json()["sessions"]
            server_session_ids = set(
                x.session_id for x in worksheet.session.session_list)

            # Group the sessions by ID
            for client_session in sessions:
                session_id = client_session.pop("session_id", None)
                server_session = worksheet.session.find_session(session_id)
                if server_session is None:
                    worksheet.session.RunPlugin("snew")
                    break

                server_session_ids.remove(session_id)

                with server_session:
                    for k, (v, _) in client_session["state"].items():
                        if not v:
                            continue

                        if (server_session.HasParameter(k) and
                                server_session.GetParameter(k) == v):
                            continue

                        logging.debug("Setting %s=%s for session %s",
                                      k, v, session_id)
                        server_session.SetParameter(k, v)

            for deleted_session_id in server_session_ids:
                worksheet.session.RunPlugin(
                    "sdel", session_id=deleted_session_id)

            # Send the updated session list to the client again.
            worksheet.StoreSessions()

            return json.dumps(worksheet.GetSessionsAsJson()), 200

    @classmethod
    def DownloadManager(cls, app):

        @app.route("/worksheet/<cell_id>/<filename>")
        def get_file(cell_id, filename):  # pylint: disable=unused-variable
            """Serve embedded files from the worksheet."""
            worksheet = app.config['worksheet']
            mimetype = request.args.get("type", "binary/octet-stream")

            data = worksheet.GetData("%s/%s" % (cell_id, filename), raw=True)
            if data:
                return data, 200, {"content-type": mimetype}

            # Not found in inventory.
            return "", 404

        @app.route("/rekall/upload/<cell_id>", methods=["POST"])
        def upload(cell_id):   # pylint: disable=unused-variable
            worksheet = app.config['worksheet']
            for in_fd in request.files.itervalues():
                # Path in the archive.
                path = "%s/%s" % (cell_id, in_fd.filename)
                with worksheet.Create(path) as out_fd:
                    utils.CopyFDs(in_fd, out_fd)

            return "OK", 200

        @app.route("/downloads/<cell_id>")
        def download_cell(cell_id):   # pylint: disable=unused-variable
            worksheet = app.config['worksheet']

            data = cStringIO.StringIO()
            with zipfile.ZipFile(
                data, mode="w", compression=zipfile.ZIP_DEFLATED) as out_fd:
                path = "%s/" % cell_id
                stored_files = set()

                for filename in worksheet.ListFiles():
                    # De-duplicate base on filename.
                    if filename in stored_files:
                        continue

                    stored_files.add(filename)
                    # Copy all files under this cell id.
                    if filename.startswith(path):
                        with worksheet.Open(filename) as in_fd:
                            # Limit reading to a reasonable size (10Mb).
                            out_fd.writestr(
                                filename[len(path):],
                                in_fd.read(100000000))

            return data.getvalue(), 200, {
                "content-type": 'binary/octet-stream',
                'content-disposition': "attachment; filename=\"%s.zip\"" % (
                    request.args.get("filename", "unknown"))}

    @classmethod
    def PlugManageDocument(cls, app):
        sockets = Sockets(app)

        @sockets.route("/rekall/document/upload")
        def upload_document(ws):  # pylint: disable=unused-variable
            cells = json.loads(ws.receive())
            if not cells:
                return

            worksheet = app.config['worksheet']
            new_data = worksheet.Encoder(cells)
            old_data = worksheet.GetData("notebook_cells", raw=True)
            if old_data != new_data:
                worksheet.StoreData("notebook_cells", new_data, raw=True)


        @app.route("/worksheet/load_nodes")
        def rekall_load_nodes():  # pylint: disable=unused-variable
            worksheet = app.config["worksheet"]
            cells = worksheet.GetData("notebook_cells") or []
            result = dict(filename=worksheet.location,
                          sessions=worksheet.GetSessionsAsJson(),
                          cells=cells)

            return json.dumps(result), 200

        @app.route("/worksheet/load_file")
        def load_new_worksheet():  # pylint: disable=unused-variable
            session = app.config['worksheet'].session
            worksheet_dir = session.GetParameter("notebook_dir", ".")
            path = os.path.normpath(request.args.get("path", ""))
            full_path = os.path.join(worksheet_dir, "./" + path)

            # First check that this is a valid Rekall file.
            try:
                fd = io_manager.ZipFileManager(full_path, mode="a")
                if not fd.GetData("notebook_cells"):
                    raise IOError
            except IOError:
                return "File is not a valid Rekall File.", 500

            old_worksheet = app.config["worksheet"]
            old_worksheet.Close()

            app.config["worksheet"] = fd

            return "Worksheet is updated", 200

        @app.route("/worksheet/save_file")
        def save_current_worksheet():  # pylint: disable=unused-variable
            """Save the current worksheet into worksheet directory."""
            worksheet = app.config['worksheet']
            session = app.config['worksheet'].session
            worksheet_dir = session.GetParameter("notebook_dir", ".")
            path = os.path.normpath(request.args.get("path", ""))
            full_path = os.path.join(worksheet_dir, "./" + path)

            with open(full_path, "wb") as out_zip:
                with zipfile.ZipFile(
                    out_zip, mode="w",
                    compression=zipfile.ZIP_DEFLATED) as out_fd:
                    cells = worksheet.GetData("notebook_cells") or []
                    out_fd.writestr("notebook_cells", json.dumps(cells))

                    for cell in cells:
                        # Copy all the files under this cell id:
                        path = "%s/" % cell["id"]
                        for filename in worksheet.ListFiles():
                            if filename.startswith(path):
                                with worksheet.Open(filename) as in_fd:
                                    # Limit reading to a reasonable size (10Mb).
                                    out_fd.writestr(
                                        filename, in_fd.read(100000000))

            worksheet.Close()

            app.config["worksheet"] = io_manager.ZipFileManager(
                full_path, mode="a")

            return "Worksheet is saved", 200

        @app.route("/worksheet/list_files")
        def list_files_in_worksheet_dir():  # pylint: disable=unused-variable
            worksheet = app.config['worksheet']
            session = worksheet.session

            try:
                worksheet_dir = os.path.abspath(worksheet.location or ".")
                full_path = os.path.abspath(os.path.join(
                    worksheet_dir, request.args.get("path", "")))

                if not os.path.isdir(full_path):
                    full_path = os.path.dirname(full_path)

                result = []
                for filename in sorted(os.listdir(full_path)):
                    if filename.startswith("."):
                        continue

                    file_stat = os.stat(os.path.join(full_path, filename))
                    file_type = "file"
                    if stat.S_ISDIR(file_stat.st_mode):
                        file_type = "directory"

                    full_file_path = os.path.join(full_path, filename)

                    # If the path is within the worksheet - make it relative to
                    # the worksheet.
                    relative_file_path = os.path.relpath(
                        full_file_path, worksheet_dir)

                    if not relative_file_path.startswith(".."):
                        full_file_path = relative_file_path

                    result.append(
                        dict(name=filename,
                             path=full_file_path,
                             type=file_type,
                             size=file_stat.st_size))

                # If the path is within the worksheet - make it relative
                # to the worksheet.
                relative_path = os.path.relpath(full_path, worksheet_dir)
                if not relative_path.startswith(".."):
                    full_path = relative_path

                return jsonify(files=result, path=full_path)
            except (IOError, OSError) as e:
                return str(e), 500

        @app.route("/uploads/worksheet", methods=["POST"])
        def upload_new_worksheet():  # pylint: disable=unused-variable
            """Replace worksheet with uploaded file."""
            worksheet = app.config['worksheet']
            session = app.config['worksheet'].session
            worksheet_dir = session.GetParameter("notebook_dir", ".")

            for in_fd in request.files.itervalues():
                path = os.path.normpath(in_fd.filename)
                full_path = os.path.join(worksheet_dir, "./" + path)

                with open(full_path, "wb") as out_fd:
                    utils.CopyFDs(in_fd, out_fd)

            return "OK", 200

        @app.route("/downloads/worksheet")
        def download_worksheet():  # pylint: disable=unused-variable
            worksheet = app.config["worksheet"]
            data = cStringIO.StringIO()
            with zipfile.ZipFile(
                data, mode="w", compression=zipfile.ZIP_DEFLATED) as out_fd:
                cells = worksheet.GetData("notebook_cells") or []
                out_fd.writestr("notebook_cells", json.dumps(cells))

                for cell in cells:
                    # Copy all the files under this cell id:
                    path = "%s/" % cell["id"]
                    for filename in worksheet.ListFiles():
                        if filename.startswith(path):
                            with worksheet.Open(filename) as in_fd:
                                # Limit reading to a reasonable size (10Mb).
                                out_fd.writestr(filename, in_fd.read(100000000))

            return data.getvalue(), 200, {
                "content-type": 'binary/octet-stream',
                'content-disposition': "attachment; filename='rekall_file.zip'"
                }

    @classmethod
    def PlugRunPluginsIntoApp(cls, app):
        sockets = Sockets(app)
        thread_pool = threadpool.ThreadPool(5)

        @app.route("/rekall/runplugin/cancel/<cell_id>", methods=["POST"])
        def cancel_execution(cell_id):  # pylint: disable=unused-variable
            worksheet = app.config["worksheet"]
            # Signal the worksheet to abort this cell.
            worksheet.aborted_cells.add(int(cell_id))

            return "OK", 200

        @sockets.route("/rekall/runplugin")
        def rekall_run_plugin_socket(ws):  # pylint: disable=unused-variable
            cell = json.loads(ws.receive())
            cell_id = cell["cell_id"]
            source = cell["source"]
            worksheet = app.config["worksheet"]

            # If the data is cached locally just return it.
            cache_key = GenerateCacheKey(source)
            cache = worksheet.GetData("%s.data" % cell_id)
            if cache and cache.get("cache_key") == cache_key:
                logging.debug("Dumping request from cache")
                ws.send(json.dumps(cache.get("data")))
                return

            kwargs = source.get("arguments", {})

            # Must provide the correct session to run this on.
            session_id = int(source.pop("session_id"))
            session = worksheet.session.find_session(session_id)

            output = cStringIO.StringIO()
            output_queue = Queue.Queue()
            renderer = WebConsoleRenderer(
                session=session, output=output, cell_id=cell_id,
                output_queue=output_queue, worksheet=worksheet)

            # Clear the interruption state of this cell.
            worksheet.aborted_cells.discard(cell_id)

            def RunPlugin():
                with renderer.start():
                    try:
                        session.RunPlugin(
                            source["plugin"]["name"],
                            renderer=renderer, **kwargs)

                    except Exception:
                        message = traceback.format_exc()
                        renderer.report_error(message)
            run_plugin_result = thread_pool.spawn(RunPlugin)

            sent_messages = []
            def HandleSentMessages():
                while not run_plugin_result.ready() or not output_queue.empty():
                    while not output_queue.empty():
                        message = output_queue.get()
                        sent_messages.append(message)
                        ws.send(json.dumps([message],
                                           cls=json_renderer.RobustEncoder))
                    run_plugin_result.wait(0.1)
            handle_messages_thread = gevent.spawn(HandleSentMessages)

            gevent.joinall([run_plugin_result, handle_messages_thread])

            # Cache the data in the worksheet.
            worksheet.StoreData("%s.data" % cell_id, dict(
                cache_key=cache_key,
                data=sent_messages))

    @classmethod
    def PlugIntoApp(cls, app):
        super(RekallRunPlugin, cls).PlugIntoApp(app)

        cls.PlugListPluginsIntoApp(app)
        cls.PlugRunPluginsIntoApp(app)
        cls.PlugManageDocument(app)
        cls.DownloadManager(app)
        cls.SessionManager(app)
