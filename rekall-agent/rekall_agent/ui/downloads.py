# Rekall Memory Forensics
#
# Copyright 2016 Google Inc. All Rights Reserved.
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

"""Plugins to ease fetching and viewing files."""

from rekall_agent import common
from rekall_agent.ui import flows
from rekall_agent.ui import renderers


class AgentControllerFetch(flows.FlowLauncherAndWaiterMixin,
                           common.AbstractControllerCommand):
    name = "fetch"

    __args = [
        dict(name="path", required=True, positional=True,
             help="The path to fetch."),
    ]

    table_header = [
        dict(name="Message")
    ]

    table_options = dict(
        suppress_headers=True
    )

    CLIENT_REQUIRED = True

    def collect(self):
        path = self.plugin_args.path
        # Allow path to be a vfs link.
        if path.startswith("vfs:"):
            path = path[4:]

        launch_flow_plugin = self.session.plugins.launch_flow(
            flow="FileFinderFlow",
            args=dict(
                globs=[path],
                download=True
            )
        )

        flow_obj = launch_flow_plugin.make_flow_object()
        yield dict(Message="Launching flow to fetch %s" % path)

        for ticket in self.launch_and_wait(flow_obj):
            for upload in ticket.files:
                link = renderers.UILink(
                    "gs", upload.get_canonical().to_path())
                yield dict(Message=link, nowrap=True)
