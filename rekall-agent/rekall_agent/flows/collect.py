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
import time

from rekall_agent import flow
from rekall_agent import result_collections
from rekall_agent.client_actions import collect as collect_action


class CollectFlow(flow.Flow):
    """Create a collection and upload it.

    This flow defines an EFilter query string, and a collection definition, and
    creates client Action()s from these. It is meant as a shorthand for writing
    more complete flows.

    """
    __abstract = True

    # This is the EFilter query and possible parameters. It is a dict with key
    # being the Rekall live mode and value being the query to run in that
    # mode. The mode is selected from the Flow.session.live parameter.
    _query = {}

    schema = [
        dict(name="query_parameters", type="dict"),
    ]

    # The columns to add to the collection spec.
    _columns = []

    _collection_name = "collection"

    def set_collection_name(self, name):
        self._collection_name = name

    def expand_collection_name(self):
        return self._collection_name.format(
            timestamp=int(time.time()),
            flow_id=self.flow_id,
        )

    def get_location(self):
        """Work out where the agent should store the collection."""
        if self.is_hunt():
            return self._config.server.hunt_vfs_path_for_client(
                self.flow_id, self.expand_collection_name(),
                expiration=self.expiration())

        return self._config.server.vfs_path_for_client(
            self.client_id, self.expand_collection_name(),
            expiration=self.expiration())

    def generate_actions(self):
        # Make a collection to store the result.
        collection = result_collections.GenericSQLiteCollection.from_keywords(
            session=self._session,
            type=self._collection_type,
            location=self.get_location(),
            tables=[
                dict(name="default", columns=self._columns)
            ],
        )

        yield collect_action.CollectAction.from_keywords(
            session=self._session,
            query=self._query,
            query_parameters=self.query_parameters,
            collection=collection
        )


class ListProcessesFlow(CollectFlow):
    """Collect data about all processes."""
    _query = dict(
        mode_live_api=(
            "select Name as name, pid, ppid, start from pslist()"),
        mode_linux_memory=(
            "select proc.name, proc.pid, ppid, start_time from pslist()")
    )

    _collection_type = "pslist"
    _columns = [
        dict(name="name", type="unicode"),
        dict(name="pid", type="int"),
        dict(name="ppid", type="int"),
        dict(name="start_time", type="epoch"),
    ]
    _collection_name = "pslist"
