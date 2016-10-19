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

"""The OSQuery plugin can capture the result of osquery queries and store in
Rekall result collections.

Note that we do not actually process the query itself, we just relay the query
to osqueryi and then write its output in a collection to be uploaded.
"""
import json
import subprocess

from rekall_agent.config import agent
from rekall_agent import action
from rekall_agent import location
from rekall_agent import result_collections


class OSQueryConfiguration(agent.PluginConfiguration):
    """Configure OSQuery."""
    schema = [
        dict(name="binary_path", default="/usr/bin/osqueryi",
             doc="Path to the osquery binary."),
    ]


class OSQueryAction(action.Action):
    """Runs the OSQuery query and stores the result.

    Note that the collection format (i.e. the columns) is determined by OSQuery
    itself based on the query. So a user does not need to specify a collection
    explicitly.
    """

    schema = [
        dict(name="query",
             doc="The OSQuery query to run."),
        dict(name="location", type=location.Location,
             doc="The result collection's final location."),
    ]

    _collection = None

    def _make_collection(self, row):
        # We need to make a new result collection definition based on the
        # row. There are a couple of problems with OSQuery's json output:

        # 1) There is no order preservation in the row which means we dont have
        # stable column ordering in our own collection.

        # 2) The json output always uses strings, even if the table is
        # internally a BIGINT. We have no choice but to make our collection use
        # strings too unless we want to guess the type based on the first few
        # rows?
        table = result_collections.Table.from_keywords(
            session=self._session, name="default")

        for row_name in row:
            table.columns.append(dict(name=row_name, type="unicode"))

        result = result_collections.GenericSQLiteCollection.from_keywords(
            session=self._session,
            location=self.location,
            tables=[table])

        result.create_temp_file()
        return result

    def run(self, flow_obj=None):
        if not self.is_active():
            return []

        osquery_path = self._config.client.plugin_config(
            OSQueryConfiguration).binary_path
        json_result = json.loads(
            subprocess.check_output([osquery_path, "--json", self.query]))

        for row in json_result:
            if self._collection is None:
                self._collection = self._make_collection(row)

            self._collection.insert(**row)

        # Ok we are done with this collection.
        if self._collection:
            self._collection.close()
