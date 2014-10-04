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
import os
import sys
import tempfile
import time
import threading
import webbrowser

from rekall import io_manager
from rekall import plugin
from rekall import utils
from rekall import testlib

from rekall.plugins.tools.webconsole import pythoncall
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
        "/rekall-webconsole/webconsole.js",
        ]


class WebConsole(plugin.Command):
    """Launch the web-based Rekall console."""

    __name = "webconsole"

    @classmethod
    def args(cls, parser):
        super(WebConsole, cls).args(parser)

        parser.add_argument("worksheet", required=False,
                            help="The worksheet file name to use (optional). "
                            "If not specified we start with a new file.")

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

    def __init__(self, host="localhost", port=0, debug=False,
                 browser=False, worksheet=None, **kwargs):
        super(WebConsole, self).__init__(**kwargs)
        self.host = host
        self.port = port
        self.debug = debug
        self.browser = browser
        self.pre_load = worksheet

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

    def render(self, renderer):
        renderer.format("Starting Manuskript web console.\n")
        renderer.format("Press Ctrl-c to return to the interactive shell.\n")


        with tempfile.NamedTemporaryFile(delete=True) as temp_fd:
            logging.info("Using working file %s", temp_fd.name + "_")

            # We need to copy the pre load file into the working file.
            if self.pre_load:
                with open(self.pre_load, "rb") as in_fd:
                    utils.CopyFDs(in_fd, temp_fd)

                logging.info("Initialized from %s", self.pre_load)

            self.worksheet_fd = io_manager.ZipFileManager(
                temp_fd.name + ".zip", mode="a")

            try:
                app = manuskript_server.InitializeApp(
                    plugins=[manuskript_plugins.PlainText,
                             manuskript_plugins.Markdown,
                             pythoncall.RekallPythonCall,
                             runplugin.RekallRunPlugin,
                             RekallWebConsole],
                    config=dict(
                        rekall_session=self.session,
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

                server = pywsgi.WSGIServer((self.host, self.port), app,
                                           handler_class=WebSocketHandler)

                t = threading.Thread(target=self.server_post_activate_callback,
                                     args=(server,))
                t.start()

                server.serve_forever()
            finally:
                self.worksheet_fd.Close()


class TestWebConsole(testlib.DisabledTest):
    """Disable the test for this command to avoid bringing up the notebook."""
    PARAMETERS = dict(commandline="webconsole")
