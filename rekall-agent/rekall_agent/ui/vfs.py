#!/usr/bin/env python2

# Rekall Memory Forensics
# Copyright 2016 Google Inc. All Rights Reserved.
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

__author__ = "Michael Cohen <scudette@google.com>"
"""These plugins are for viewing the client's VFS.
"""
import arrow

from rekall import plugin
from rekall import utils
from rekall.plugins.response import common as response_common

from rekall_agent import common
from rekall_agent.client_actions import files
from rekall_agent.flows import find
from rekall_agent.ui import flows
from rekall_agent.ui import renderers


class VFSLs(flows.FlowLauncherAndWaiterMixin,
            common.AbstractControllerCommand):
    name = "vfs_ls"

    __args = [
        dict(name="path", positional=True, required=False, default="/",
             help="The path to list."),

        dict(name="refresh", type="Bool",
             help="If set we issue a new flow request to the client and wait "
             "until it completes."),

        dict(name="recursive", type="Bool",
             help="Recurse into subdirs."),
    ]

    table_header = [
        dict(name="P", width=1),
        dict(name="st_mode", width=11),
        dict(name="st_ino", hidden=True),
        dict(name="st_dev", hidden=True),
        dict(name="st_nlink", hidden=True),
        dict(name="st_uid", hidden=True),
        dict(name="st_gid", hidden=True),
        dict(name="st_size", width=7, align="r"),
        dict(name="st_atime", hidden=True),
        dict(name="st_mtime", hidden=True),
        dict(name="st_ctime", width=19),
        dict(name="Path"),
    ]

    def _collect_one_dir(self, vfs_index, path_components):
        path = utils.normpath(utils.join_path(*path_components))
        stat_collection_path = None
        virtual_directories = set()

        # More recent collections override older collections.
        for row in vfs_index.query(order_by="timestamp asc"):
            collection_path_components = filter(None, row["dirname"].split("/"))

            # e.g. collection_path_components = /home/
            #      path_components = /home/scudette/
            if (len(collection_path_components) <= len(path_components) and
                collection_path_components == path_components[
                    :len(collection_path_components)]):
                stat_collection_path = row["location_path"]

            # e.g. path_components = /home/
            #      collection_path_components = /home/scudette/
            elif (len(collection_path_components) > len(path_components) and
                  collection_path_components[:len(path_components)] ==
                  path_components):
                virtual_directories.add(collection_path_components[
                    len(path_components)])

        # We found a collection that contains this path.
        if stat_collection_path:
            with files.StatEntryCollection.load_from_location(
                    self._config.server.location_from_path_for_server(
                        stat_collection_path),
                    session=self.session) as stat_collection:

                for row in list(stat_collection.query(
                        dirname=path, order_by="filename")):
                    mode = response_common.Permissions(row["st_mode"] or 0)
                    result = dict(
                        Path=utils.join_path(row["dirname"], row["filename"]),
                        st_mode=mode,
                        st_size=row["st_size"],
                        st_mtime=arrow.get(row["st_mtime"]),
                        st_atime=arrow.get(row["st_atime"]),
                        st_ctime=arrow.get(row["st_ctime"]),
                    )

                    for field in "st_ino st_dev st_nlink st_uid st_gid".split():
                        result[field] = row[field]

                    yield result

                    if self.plugin_args.recursive and mode.is_dir():
                        for row in self._collect_one_dir(
                                vfs_index, path_components + [row["filename"]]):
                            yield row

        else:
            for directory in virtual_directories:
                mode = response_common.Permissions(0755)
                yield dict(Path=utils.join_path(path, directory), st_mode=mode)

                if self.plugin_args.recursive:
                    for row in self._collect_one_dir(
                            vfs_index, path_components + [directory]):
                        yield row

    def collect(self):
        path = utils.normpath(self.plugin_args.path)
        if not self.client_id:
            raise plugin.PluginError("Client ID expected.")

        # If the user asks for fresh data then launch the flow and wait for it
        # to finish.
        if self.plugin_args.refresh:
            flow_obj = self.session.plugins.launch_flow(
                flow="ListDirectory",
                args=dict(
                    path=path,
                    recursive=self.plugin_args.recursive,
                )
            ).make_flow_object()

            # Wait until the list directory is completed.
            self.launch_and_wait(flow_obj)

        # First get the VFS index.
        with find.VFSIndex.load_from_location(
                self._config.server.vfs_index_for_server(self.client_id),
                session=self.session) as vfs_index:

            # We use the index to get the best StatEntryCollection() which
            # covers the requested path. There are three possible cases:

            # 1) All the existing StatEntryCollection()s start at a directory
            #    deeper than path. In this case we emulate the directories of
            #    all existing collections' starting paths.

            # 2) The requested path begins with the starting path of one or more
            #    StatEntryCollection()s. This means these collections contain
            #    it.

            # 3) path is longer than all StatEntryCollection()'s starting paths
            #    plus their depth.

            path_components = filter(None, path.split("/"))
            for row in self._collect_one_dir(vfs_index, path_components):
                row["Path"] = renderers.UILink("vfs", row["Path"])
                yield row
