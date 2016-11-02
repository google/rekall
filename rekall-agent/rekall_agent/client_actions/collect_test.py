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

import sqlite3
import os

from rekall import plugin

# Ensure search plugin is loaded.
from rekall import plugins # pylint: disable=unused-import

from rekall import testlib
from rekall_agent import result_collections
from rekall_agent.client_actions import collect
from rekall_agent.locations import files


FAKE_DATA = [
    (1, "a", 3.5),
    (2, "b", 3.5),
]

class TestCollectionPlugin(plugin.TypedProfileCommand, plugin.Command):
    """Test plug that generates a known pattern."""
    name = "test_collection_plugin"

    table_header = [
        dict(name="c1"),
        dict(name="c2"),
        dict(name="c3"),
    ]

    def collect(self):
        return FAKE_DATA


class TestCollectClientAction(testlib.RekallBaseUnitTestCase):
    """Test the agent_collect plugin.

    The agent_collect plugin is the basis for many agent actions. It accepts an
    efilter query and a collection specification and inserts the results of the
    query into the collection.
    """

    def setUp(self):
        self.session = self.MakeUserSession()
        self.session.SetParameter("agent_config_data", "{}")

    def testCollectionAction(self):
        # The path where we want the collection to finally reside.
        final_path = os.path.join(self.temp_directory, "test.sqlite")

        # Make a SQL Collection.
        collection = result_collections.GenericSQLiteCollection.from_keywords(
            session=self.session,
            # Store the file locally.
            location=files.FileLocation.from_keywords(
                session=self.session,
                path=final_path),
            tables=[dict(name="default",
                         columns=[dict(name="c1", type="int"),
                                  dict(name="c2", type="unicode"),
                                  dict(name="c3", type="float")])],
        )

        # Create a request to the agect_collection.
        request = collect.CollectAction.from_keywords(
            session=self.session,
            query=dict(
                mode_agent="select c1, c2, c3 from test_collection_plugin()"),
            collection=collection,
        )

        # Run the plugin and collect the output.
        collections = list(request.run())

        self.assertEqual(len(collections), 1)
        self.assertEqual(collections[0].location.path, final_path)

        # Now check that the collection is complete with direct SQL.
        conn = sqlite3.connect(final_path)

        data = list(conn.execute("select * from tbl_default"))
        self.assertEqual(len(data), 2)
        self.assertEqual(data, FAKE_DATA)


if __name__ == "__main__":
    testlib.main()
