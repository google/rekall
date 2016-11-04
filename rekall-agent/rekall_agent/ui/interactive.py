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

from rekall import yaml_utils
from rekall.plugins.addrspaces import standard
from rekall_agent import common
from rekall_agent import result_collections
from rekall_agent.ui import renderers


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
        dict(name="mode", type="Choices", choices=["text", "hex"],
             help="Mode for dumping files"),
        dict(name="encoding", default="ascii",
             help="Possible encodings we try for text mode detection."),

        dict(name="offset", type="IntParser",
             default=0, help="An offset to hexdump."),
    ]

    MAX_SIZE = 10*1024*1024

    offset = None

    def render(self, renderer):
        # Starting offset.
        if self.offset is None:
            self.offset = self.plugin_args.offset

        location = self._config.server.location_from_path_for_server(
            self.plugin_args.path)

        local_filename = location.get_local_filename()

        # Map the location as a file because it could be very large.
        address_space = standard.FileAddressSpace(
            filename=local_filename, session=self.session)

        if address_space.read(0, 13) == "SQLite format":
            return self.render_sqlite(location, renderer)

        if (address_space.end() < self.MAX_SIZE and
            address_space.read(0, 1) in "{["):
            try:
                data = json.loads(address_space.read(
                    0, min(self.MAX_SIZE, address_space.end())))
                return self.render_json(data, renderer)
            except Exception:
                pass

        # Auto detect the mode.
        sample = address_space.read(
            0, min(1024 * 1024, address_space.end()))
        try:
            data = sample.decode(self.plugin_args.encoding)
            return self.render_text(
                local_filename, self.plugin_args.encoding, renderer)
        except UnicodeError:
            pass

        # Fall back to hexdump
        result = self.session.plugins.dump(
            rows=self.plugin_args.limit, offset=self.offset,
            address_space=address_space)
        result.render(renderer)
        self.offset = result.offset
        return result

    def render_text(self, local_filename, encoding, renderer):
        renderer.table_header([dict(name="File Contents")])
        with open(local_filename, "rb") as fd:
            for line in fd:
                self.offset = fd.tell()
                try:
                    renderer.table_row(line.decode(encoding))
                except UnicodeError:
                    continue

    def render_json(self, data, renderer):
        renderer.table_header([dict(name="Message")], auto_widths=True)
        renderer.table_row(yaml_utils.safe_dump(data))

    def render_sqlite(self, location, renderer):
        with result_collections.GenericSQLiteCollection.load_from_location(
                location, session=self.session) as collection:
            for table in collection.tables:
                types = []
                headers = []
                for column in table.columns:
                    col_spec = dict(name=column.name)
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
                    renderer.table_row(
                        *[fn(x or 0) for fn, x in zip(types, row)])


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
        location = self._config.server.location_from_path_for_server(
            self.plugin_args.path)

        for stat in location.list_files(max_results=self.plugin_args.limit):
            yield dict(Name=renderers.UILink("gs", stat.location.to_path()),
                       Size=stat.size,
                       Created=stat.created)
