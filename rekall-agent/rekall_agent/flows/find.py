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

        return result

    def generate_actions(self):
        # Make a collection to store the result.
        collection = files.StatEntryCollection.from_keywords(
            session=self._session,
            location=self.get_location(),
        )

        location = None
        if self.download:
            location = self._config.server.vfs_prefix_for_client(
                self.client_id, vfs_type="files", expiration=self.expiration())

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

    def validate(self):
        super(ListDirectoryFlow, self).validate()
        if not self.path:
            raise plugin.InvalidArgs("Path must be set")

    def generate_actions(self):
        yield files.ListDirectoryAction.from_keywords(
            session=self._session,
            path=self.path,
            recursive=self.recursive,
            vfs_location=self._config.server.vfs_path_for_client(
                self.client_id, self.path.rstrip("/"),
                expiration=self.expiration(), vfs_type="metadata",
                mode="w")
        )
