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

"""Plugins for interactively examining the state of the deployment."""
import json

import arrow

from rekall import utils
from rekall import yaml_utils
from rekall_agent import common
from rekall_agent import result_collections


class AgentControllerShowFile(common.AbstractControllerCommand):
    """Display information about a file."""

    name = "view"

    __args = [
        dict(name="path", positional=True, required=True,
             help="A path to the object to display."),
        dict(name="query",
             help="If this is a collection, issue this query"),
        dict(name="limit",
             help="Limit result to this many rows."),
    ]

    def render(self, renderer):
        location = self.config.server.location_from_path_for_server(
            self.plugin_args.path)

        data = location.read_file()
        if data.startswith("SQLite format"):
            return self.render_sqlite(location, renderer)

        try:
            data = json.loads(data)
            return self.render_json(data, renderer)

        except Exception:
            renderer.table_header([dict(name="Message", width=160)])
            renderer.table_row(utils.HexDumpedString(data, hex_width=30))

    def render_json(self, data, renderer):
        renderer.table_header([dict(name="Message")], auto_widths=True)
        renderer.table_row(yaml_utils.safe_dump(data))

    def render_sqlite(self, location, renderer):
        collection = (
            result_collections.GenericSQLiteCollection.load_from_location(
                location, session=self.session)
        )
        for table in collection.tables:
            types = []
            headers = []
            for column in table.columns:
                col_spec = dict(name=column.name, cname=column.name)
                if column.type == "int":
                    col_spec["align"] = "r"

                if column.type == "epoch":
                    types.append(arrow.Arrow.fromtimestamp)

                else:
                    types.append(lambda x: x)

                headers.append(col_spec)

            # If the table is too large we cant wait to auto width it.
            auto_widths = max(
                self.plugin_args.limit, len(collection)) < 1000
            renderer.table_header(headers, auto_widths=auto_widths)
            for row in collection.query(
                    table=table.name, query=self.plugin_args.query,
                    limit=self.plugin_args.limit):
                renderer.table_row(*[fn(x or 0) for fn, x in zip(types, row)])


class AgentControllerStoreLs(common.AbstractControllerCommand):
    """Show files within the storage bucket."""
    name = "bucket_ls"

    __args = [
        dict(name="path", positional=True,
             help="A path to the object to display."),

        dict(name="limit", type="IntParser", default=100,
             help="Total results to display"),

    ]

    table_header = [
        dict(name="Size", width=10),
        dict(name="Created", width=25),
        dict(name="Name"),
    ]

    def collect(self):
        location = self.config.server.location_from_path_for_server(
            self.plugin_args.path)

        for stat in location.list_files(max_results=self.plugin_args.limit):
            yield dict(Name=stat.location.to_path(),
                       Size=stat.size,
                       Created=stat.created)
