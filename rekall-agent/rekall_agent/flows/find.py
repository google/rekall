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

from rekall_agent import common
from rekall_agent import flow
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
            column_spec[x.name] = "Path.%s" % x.name

        column_spec["st_mode_str"] = "str(Path.st_mode)"
        column_spec["st_uid"] = "Path.st_uid.uid"
        column_spec["st_gid"] = "Path.st_gid.gid"

        columns = ["%s as %s" % (v, k) for k, v in column_spec.items()]

        result = (
            "select %s from stat(paths: (glob(?).path.filename.name))" %
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
            query_parameters=self.globs,
            collection=collection,
            location=location
        )


class ListDirectoryFlow(flow.Flow):
    schema = [
        dict(name="path", user=True,
             doc="The name of the directory to list."),

        dict(name="recursive", type="bool", user=True,
             doc="If set we recursively list all directories."),
    ]

    def get_location(self):
        """Work out where the agent should store the collection."""
        if self.is_hunt():
            return self._config.server.hunt_vfs_path_for_client(
                self.flow_id, self.path, vfs_type="metadata",
                expiration=self.expiration())

        return self._config.server.vfs_path_for_client(
            self.client_id, self.path,
                expiration=self.expiration(), vfs_type="collections",
                mode="w")

    def validate(self):
        super(ListDirectoryFlow, self).validate()
        if not self.path:
            raise plugin.InvalidArgs("Path must be set")

    def generate_actions(self):
        yield files.ListDirectoryAction.from_keywords(
            session=self._session,
            path=self.path,
            recursive=self.recursive,
            vfs_location=self.get_location(),
        )

    def _write_collection(self, directory, rows):
        print "Writing %d rows on %s" % (len(rows), directory)
        config = self._session.GetParameter("agent_config")

        def _copy_into_collection(col):
            for row in rows:
                col.insert(row=row)

        # Write the rows into the new collection.
        files.StatEntryCollection.transaction(
            config.server.vfs_path_for_server(
                self.client_id, directory, vfs_type="metadata"),
            #lambda col: (col.insert(row=x) for x in rows),
            _copy_into_collection,
            session=self._session)

    def post_process(self, tickets):
        """Post process the list directory collection.

        We want to maintain an easier to navigate view of the client's VFS in
        the client's namespace. We place a StatEntryCollection at each directory
        location and write all the files within that directory.
        """
        super(ListDirectoryFlow, self).post_process(tickets)

        if self.is_hunt():
            return

        config = self._session.GetParameter("agent_config")

        results = []

        for ticket in tickets:
            for collection in ticket.collections:
                result_collection = collection.load_from_location(
                    config.server.location_from_path_for_server(
                        collection.location.to_path()),
                    session=self._session)

                # Collect all the rows with the same directory path.
                directory_rows = []
                last_directory = None
                for row in result_collection.query(order_by="rowid"):
                    if last_directory is None:
                        last_directory = row["dirname"]

                    if last_directory == row["dirname"]:
                        directory_rows.append(row)
                    else:
                        # The new row is not in the last_directory, flush the
                        # directory_rows and start again.
                        results.append(common.THREADPOOL.apply_async(
                        #results.append(common.THREADPOOL.apply(
                            self._write_collection,
                            (last_directory, directory_rows)))

                        last_directory = row["dirname"]
                        directory_rows = [row]

                if last_directory and directory_rows:
                    self._write_collection(last_directory, directory_rows)

        # Wait for all the threads to finish.
        for result in results:
            result.get()
