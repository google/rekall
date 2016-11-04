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

"""An object which is invoked to process the results of a flow."""


from rekall_agent import result_collections
from rekall_agent import serializer


class OutputPlugin(serializer.SerializedObject):
    """An output plugin is invoked on the results of a flow."""

    def post_process(self, flow_obj, ticket):
        """Post process the flow with the ticket."""


class MergeHuntCollections(OutputPlugin):
    """Merges all client collections into a hunt wide collection."""

    def _copy_collections(self, dest_collection, data):
        for collection, client_id in data:
            with collection.load_from_location(
                    self._config.server.canonical_for_server(
                        collection.location),
                    session=self._session) as src_collection:
                for row in src_collection.query():
                    dest_collection.insert(client_id=client_id, **row)

    def post_process(self, flow_obj, tickets):
        self._config = self._session.GetParameter("agent_config")
        collections_by_type = {}

        for ticket in tickets:
            if ticket.status == "Done":
                for collection in ticket.collections:
                    collection_type = (collection.type or
                                       collection.__class__.__name__)

                    collections_by_type.setdefault(collection_type, []).append(
                        (collection, ticket.client_id))

        for collection_type, data in collections_by_type.iteritems():
            first_collection = data[0][0]

            # Create the destination collection modeled after the first
            # collection.
            dest_collection = first_collection.copy()

            # Add a client id column.
            dest_collection.tables[0].columns.insert(
                0, result_collections.ColumnSpec.from_keywords(
                    session=self._session,
                    name="client_id"))

            result_collections.GenericSQLiteCollection.transaction(
                self._config.server.hunt_result_collection_for_server(
                    flow_obj.flow_id, collection_type),
                self._copy_collections,
                data,
                default_collection=dest_collection,
                session=self._session)
