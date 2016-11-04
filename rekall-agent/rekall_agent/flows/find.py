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
"""This implements the file finder flow.

This flow is the workhorse of filesystem operations.
"""
import collections
from rekall import plugin
from rekall import utils

from rekall_agent import flow
from rekall_agent import result_collections
from rekall_agent import serializer
from rekall_agent.client_actions import download
from rekall_agent.client_actions import files
from rekall_agent.flows import collect


class FileFilterCondition(serializer.SerializedObject):
    """Baseclass for all file filter conditions."""

    def get_efilter_clause(self):
        return "1"


class ModificationTimeCondition(FileFilterCondition):
    schema = [
        dict(name="min", type="epoch", default=None,
             doc="Only select files that have an mtime after "
             "this value."),

        dict(name="max", type="epoch", default=None,
             doc="Only select files that have an mtime before "
             "this value."),
    ]

    def get_efilter_clause(self):
        result = []
        if self.min:
            result.append("Path.st_mtime > %s" % self.min)

        if self.max:
            result.append("Path.st_mtime < %s" % self.max)

        return "(" + " and ".join(result) + ")"


class FileFinderFlow(collect.CollectFlow):
    _collection_name = "file_finder_{timestamp}"

    schema = [
        dict(name="globs", repeated=True, user=True,
             doc="Globs to search in client."),

        dict(name="conditions", type=FileFilterCondition, repeated=True,
             doc="One or more filter conditions to restrict results."),

        dict(name="download", type="bool", user=True,
             doc="Should we download the file?"),

        dict(name="path_sep",
             doc="Glob path separator"),
    ]

    def validate(self):
        super(FileFinderFlow, self).validate()
        if not self.globs:
            raise plugin.InvalidArgs("Some globs must be provided.")

    def create_query(self, collection):
        """Make an efilter query from all the flow parameters.

        Combines the high level FileFinder filter specifications to actionable
        efilter query.
        """
        # This code just saves some typing :-).
        column_spec = collections.OrderedDict()
        for x in collection.tables[0].columns:
            column_spec[x.name] = "path.%s" % x.name

        column_spec["dirname"] = "path.filename.dirname"
        column_spec["filename"] = "path.filename.basename"
        column_spec["st_mode_str"] = "str(path.st_mode)"
        column_spec["st_uid"] = "path.st_uid.uid"
        column_spec["st_gid"] = "path.st_gid.gid"

        columns = ["%s as %s" % (v, k) for k, v in column_spec.items()]

        result = (
            "select %s from glob({globs}, path_sep: {path_sep})" %
            ",".join(columns))

        # Filter conditions are specified.
        if self.conditions:
            parts = [x.get_efilter_clause() for x in self.conditions]
            result += " where " + " and ".join(parts)

        return dict(mode_live=result)

    def generate_actions(self):
        # Make a collection to store the result.
        collection = files.StatEntryCollection.from_keywords(
            session=self._session,
            location=self.get_location(),
        )

        location = None
        if self.download:
            if self.is_hunt():
                location = self._config.server.hunt_vfs_path_for_client(
                    self.flow_id, vfs_type="files",
                    path_template="{client_id}/{subpath}",
                    expiration=self.expiration())
            else:
                location = self._config.server.vfs_prefix_for_client(
                    self.client_id, vfs_type="files",
                    expiration=self.expiration())

        yield download.GetFiles.from_keywords(
            session=self._session,
            query=self.create_query(collection),
            query_parameters=dict(globs=self.globs,
                                  path_sep=self.path_sep),
            collection=collection,
            location=location
        )


class VFSIndex(result_collections.GenericSQLiteCollection):
    """The VFS index manages the VFS.

    The VFS is constructed by merging one or more different StatEntryCollection
    collections into a single coherent view. In order to know which
    StatEntryCollection represents which specific directory we need a fast
    lookup index - which is managed in this collection.
    """
    _tables = [dict(
        name="default",

        # Each entry represents one StatEntryCollection().
        columns=[
            # The top level directory contained in this collection.
            dict(name="dirname"),

            # The end depth of this collection.
            dict(name="end_depth", type="int"),

            # The age of this collection.
            dict(name="timestamp", type="epoch"),

            # Where it is.
            dict(name="location_path"),
        ]
    )]


class ListDirectory(flow.Flow):
    """Maintain the client VFS view.

    Rekall maintains a view of the client's filesystem called the VFS (Virtual
    File System). The view is maintained by collecting stat() entries from the
    client in many StatEntryCollection() collections and storing them in the
    client's bucket namespace.

    This flow (ListDirectory) is responsible for creating and managing these
    collections into a unified VFS that can be browsed with the `vfs_ls` and
    `vfs_cp` plugins.
    """

    schema = [
        dict(name="path", user=True,
             doc="The name of the directory to list."),

        dict(name="depth", type="int", default=1, user=True,
             doc="If set we recursively list all directories."),
    ]

    def get_location(self):
        """Work out where the agent should store the collection."""
        if self.is_hunt():
            return self._config.server.hunt_vfs_path_for_client(
                self.flow_id, self.path, vfs_type="metadata",
                expiration=self.expiration())

        return self._config.server.vfs_path_for_client(
            self.client_id, "%s/%s" % (self.path, self.flow_id),
            expiration=self.expiration(), vfs_type="collections",
            mode="w")

    def validate(self):
        super(ListDirectory, self).validate()
        if not self.path:
            raise plugin.InvalidArgs("Path must be set")

    def generate_actions(self):
        yield files.ListDirectoryAction.from_keywords(
            session=self._session,
            path=self.path,
            depth=self.depth,
            vfs_location=self.get_location(),
        )

    def post_process(self, tickets):
        """Post process the list directory collection.

        We want to maintain an easier to navigate view of the client's VFS in
        the client's namespace. We place a StatEntryCollection at each directory
        location and write all the files within that directory.
        """
        super(ListDirectory, self).post_process(tickets)

        if self.is_hunt():
            return

        VFSIndex.transaction(
            self._config.server.vfs_index_for_server(self.client_id),
            self._update_vfs_index,
            tickets,
            session=self._session)

    def _update_vfs_index(self, index_collection, tickets):
        """Extract all the directories and store them in the index."""
        path = utils.normpath(self.path)
        for ticket in tickets:
            for collection in ticket.collections:
                index_collection.insert(
                    dirname=path,
                    timestamp=ticket.timestamp,
                    location_path=collection.location.to_path())
