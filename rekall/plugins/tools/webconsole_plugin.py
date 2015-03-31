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

import logging
import json
import os
import re
import shutil
import sys
import time
import threading
import webbrowser

from rekall import constants
from rekall import io_manager
from rekall import plugin
from rekall import testlib
from rekall import yaml_utils

from rekall.ui import renderer

from rekall.plugins.tools.webconsole import runplugin

from flask import Blueprint

from gevent import pywsgi
from geventwebsocket.handler import WebSocketHandler

from manuskript import plugins as manuskript_plugins
from manuskript import plugin as manuskript_plugin
from manuskript import server as manuskript_server


try:
    STATIC_PATH = os.path.join(sys._MEIPASS, "webconsole", "static")  # pylint: disable=protected-access
except AttributeError:
    STATIC_PATH = os.path.join(os.path.dirname(__file__), "webconsole",
                               "static")


class RekallWebConsole(manuskript_plugin.Plugin):

    ANGULAR_MODULE = "rekall.webconsole"

    JS_FILES = [
        "rekall-webconsole/webconsole.js",
        ]


class WebConsoleDocument(io_manager.DirectoryIOManager):
    """A stable, version control friendly Document manager.

    In order to properly version control the Rekall document it is more
    convenient to have it in a directory structure with stable serialization.

    This IOManager implements this kind of format. To use it just point the web
    console at a directory.
    """

    __abstract = True

    def __init__(self, path, **kwargs):
        super(WebConsoleDocument, self).__init__(path, version="", **kwargs)
        # The front end can request execution on cell ids to be interrupted by
        # setting the cell id here.
        self.aborted_cells = set()

    def Create(self, name):
        path = self._GetAbsolutePathName(name)
        self.EnsureDirectoryExists(os.path.dirname(path))

        return open(path, "wb")

    def Encoder(self, data):
        return yaml_utils.encode(data)

    def Decoder(self, raw_data):
        return yaml_utils.decode(raw_data)

    def FlushInventory(self):
        """Clean up deleted cells."""
        cells = self.GetData("notebook_cells")
        if cells:
            cells_to_leave = set([str(cell["id"]) for cell in cells])
            for path in os.listdir(self.dump_dir):
                m = re.match(r"^(\d+)\.data$", path)
                if m and m.group(1) not in cells_to_leave:
                    logging.debug("Trimming cell file %s", path)
                    os.unlink(self._GetAbsolutePathName(path))
                    continue

                m = re.match(r"^\d+$", path)
                if m and path not in cells_to_leave:
                    logging.debug("Trimming cell directory %s", path)
                    shutil.rmtree(self._GetAbsolutePathName(path))

    def StoreSessions(self):
        """Store the sessions in the document."""
        # Save all the sessions for next time.
        self.StoreData("sessions", self.GetSessionsAsJson())
        self.StoreData("metadata.rkl", self.metadata)

    def LoadSession(self):
        self.metadata = self.GetData("metadata.rkl")
        if not self.metadata:
            self.metadata = dict(
                version=constants.VERSION,
                codename=constants.CODENAME,
                tool="Rekall Forensic"
            )

        # Restore all the sessions from the document.
        sessions = self.GetData("sessions")
        if sessions:
            # First clear existing sessions.
            del self.session.session_list[:]

            # Now restore all sessions.
            for session in sessions:
                kwargs = {}
                kwargs["session_id"] = session.get("session_id")
                for k, v in session.get("state", {}).iteritems():
                    item = v[0]
                    if isinstance(item, dict):
                        mro = item.get("mro")
                        if mro:
                            object_renderer = renderer.ObjectRenderer.FromMRO(
                                mro, "JsonRenderer")(renderer="JsonRenderer")
                            item = object_renderer.DecodeFromJsonSafe(item, {})

                    kwargs[k] = item

                new_session = self.session.clone(**kwargs)
                self.session.session_list.append(new_session)

            # Now switch to the first session in the list.
            self.session = self.session.session_list[0]

    def __enter__(self):
        self.LoadSession()
        return self

    def GetSessionsAsJson(self):
        sessions = []
        for session in self.session.session_list:
            # Serialize the session and append it to the sessions list.
            object_renderer = renderer.ObjectRenderer.ForTarget(
                session, "DataExportRenderer")(
                    session=session, renderer="DataExportRenderer")

            sessions.append(object_renderer.EncodeToJsonSafe(session))

        return sessions

    def __exit__(self, exc_type, exc_value, trace):
        self.StoreSessions()


class WebConsole(plugin.Command):
    """Launch the web-based Rekall console."""

    __name = "webconsole"

    @classmethod
    def args(cls, parser):
        super(WebConsole, cls).args(parser)

        parser.add_argument("worksheet", required=True,
                            help="The worksheet directory name to use. ")

        parser.add_argument("--host", default="localhost",
                            help="Host for the web console to use.")

        parser.add_argument("--port", default=0, type="IntParser",
                            help="Port for the web console to use.")

        parser.add_argument("--debug", default=False, type="Boolean",
                            help="Start in the debug mode (will monitor "
                            "changes in the resources and reload them as "
                            "needed.")

        parser.add_argument("--browser", default=False, type="Boolean",
                            help="Open webconsole in the default "
                            "browser.")

        parser.add_argument("--export", default=None, type="String",
                            help="When specified we export a static page to "
                            "this path.")

        parser.add_argument(
            "--export-root-url-path", default=None, type="String",
            help="The filesystem path where the root URL will be during "
            "static export.")

    PLUGINS = [manuskript_plugins.PlainText,
               manuskript_plugins.Markdown,
               manuskript_plugins.Shell,
               manuskript_plugins.PythonCall,
               runplugin.RekallRunPlugin,
               RekallWebConsole]

    def __init__(self, worksheet=None, host="localhost", port=0, debug=False,
                 browser=False, export=None, export_root_url_path=".",
                 **kwargs):
        super(WebConsole, self).__init__(**kwargs)
        self.host = host
        self.port = port
        self.debug = debug
        self.browser = browser
        self.worksheet_path = os.path.abspath(worksheet)
        if export is not None:
            export = os.path.abspath(export)

        if export_root_url_path is not None:
            export_root_url_path = os.path.abspath(export_root_url_path)

        self.export = export
        self.export_root_url_path = export_root_url_path

    def _copytree(self, src, dst):
        """A variant of shutil.copytree.

        This version is simpler does not copy files which are not changed.
        """
        names = os.listdir(src)
        # Make sure the directory exists.
        try:
            os.makedirs(dst)
        except EnvironmentError:
            pass

        for name in names:
            srcname = os.path.join(src, name)
            dstname = os.path.join(dst, name)
            try:
                if os.path.isdir(srcname):
                    self._copytree(srcname, dstname)

                else:
                    src_m_time = int(os.stat(srcname).st_mtime)
                    if (not os.path.isfile(dstname) or
                            src_m_time != int(os.stat(dstname).st_mtime)):
                        shutil.copy2(srcname, dstname)
                        logging.debug("Copied %s->%s", srcname, dstname)

            except EnvironmentError, why:
                logging.debug("Unable to copy %s->%s: %s",
                              srcname, dstname, why)

    def Export(self, path):
        output_io_manager = WebConsoleDocument(path, mode="w")

        output_io_manager.StoreData(
            "index.html",
            manuskript_server.ExpandManuskriptHeaders(
                self.PLUGINS, root_url="/", mode='static'),
            raw=True)

        cells = self.worksheet_fd.GetData("notebook_cells") or []
        result = dict(filename=self.worksheet_fd.location,
                      sessions=self.worksheet_fd.GetData("sessions"),
                      cells=cells)

        output_io_manager.StoreData("worksheet/load_nodes",
                                    json.dumps(result), raw=True)

        # Copy the static directories.
        self._copytree(STATIC_PATH, os.path.join(
            self.export_root_url_path, "rekall-webconsole"))

        self._copytree(manuskript_server.STATIC_PATH, os.path.join(
            self.export_root_url_path, "static"))

        for cell in cells:
            data = None
            if cell["type"] == "rekallplugin":
                data = self.worksheet_fd.GetData("%s.data" % cell["id"])
            elif cell["type"] == "shell":
                data = self.worksheet_fd.GetData("%s/shell" % cell["id"])
            elif cell["type"] == "pythoncall":
                data = self.worksheet_fd.GetData("%s/python" % cell["id"])
            elif cell["type"] == 'fileupload':
                # Copy all the files out.
                for item in cell.get("source", {}).get("files", []):
                    item_name = "%s/%s" % (cell["id"], item.get("name"))
                    file_data = self.worksheet_fd.GetData(
                        item_name, raw=True)
                    if file_data:
                        output_io_manager.StoreData(
                            "worksheet/" + item_name, file_data, raw=True)

            if data:
                output_io_manager.StoreData("worksheet/%s.json" % cell["id"],
                                            json.dumps(data), raw=True)

    def server_post_activate_callback(self, server):
        time.sleep(1)

        # Update the port number, because the server may have launched on a
        # random port.
        self.port = server.server_port
        if self.browser:
            webbrowser.open("http://%s:%d" % (self.host, self.port))
        else:
            sys.stderr.write(
                "Server running at http://%s:%d\n" % (self.host, self.port))

    def _serve_wsgi(self):
        with self.worksheet_fd:
            app = manuskript_server.InitializeApp(
                plugins=self.PLUGINS,
                config=dict(
                    worksheet=self.worksheet_fd,
                ))

            # Use blueprint as an easy way to serve static files.
            bp = Blueprint('rekall-webconsole', __name__,
                           static_url_path="/rekall-webconsole",
                           static_folder=STATIC_PATH)

            @bp.after_request
            def add_header(response):  # pylint: disable=unused-variable
                response.headers['Cache-Control'] = 'no-cache, no-store'
                return response

            app.register_blueprint(bp)

            # Use blueprint as an easy way to serve static files.
            bp = Blueprint('worksheet', __name__,
                           static_url_path="/worksheet",
                           static_folder=self.worksheet_path)

            @bp.after_request
            def add_header(response):  # pylint: disable=unused-variable
                response.headers['Cache-Control'] = 'no-cache, no-store'
                return response

            app.register_blueprint(bp)

            server = pywsgi.WSGIServer(
                (self.host, self.port), app,
                environ={'wsgi.multithread': True},
                handler_class=WebSocketHandler)

            t = threading.Thread(target=self.server_post_activate_callback,
                                 args=(server,))
            t.start()

            server.serve_forever()

    def render(self, renderer_obj):
        renderer_obj.format("Starting Manuskript web console.\n")
        renderer_obj.format(
            "Press Ctrl-c to return to the interactive shell.\n")

        # Handle the special file association .rkl
        if (not os.path.isdir(self.worksheet_path) and
            self.worksheet_path.endswith(".rkl")):
            self.worksheet_path = os.path.dirname(self.worksheet_path)

        if os.path.isdir(self.worksheet_path):
            # Change path to the worksheet_path to ensure relative filenames
            # work.
            cwd = os.getcwd()
            try:
                os.chdir(self.worksheet_path)
                self.worksheet_fd = WebConsoleDocument(
                    self.worksheet_path, session=self.session)

                if self.export is not None:
                    return self.Export(self.export)

                return self._serve_wsgi()

            finally:
                os.chdir(cwd)

        raise plugin.PluginError("Worksheet path must be a directory.")


class TestWebConsole(testlib.DisabledTest):
    """Disable the test for this command to avoid bringing up the notebook."""
    PARAMETERS = dict(commandline="webconsole")
