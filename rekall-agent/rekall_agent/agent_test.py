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
import json
import os
import uuid

from rekall import testlib
from rekall_agent import agent as rekall_agent
from rekall_lib import serializer
from rekall_lib.rekall_types import agent


class TestAgent(testlib.RekallBaseUnitTestCase):
    def setUp(self):
        self.session = self.MakeUserSession()

    def testAgent(self):
        flow_data = dict(
            __type__="Flow",
            rekall_session=dict(live="API", logging_level="debug"),
            ticket=dict(
                location=dict(
                    __type__="FileLocation",
                    path_prefix=self.temp_directory,
                    path_template="ticket.json",
                )),
            actions=[
                dict(__type__="PluginAction",
                     plugin="Search",
                     args=dict(
                         query="select proc from pslist() where proc.pid < 10"),
                     collection=dict(
                         __type__="JSONCollection",
                         id=str(uuid.uuid4()),
                         location=dict(
                             __type__="FileLocation",
                             path_prefix=self.temp_directory,
                             path_template="collection.json"),
                     ))
                ])

        # Validate the data
        flow_obj = serializer.unserialize(
            flow_data, session=self.session, strict_parsing=True)
        statuses = [x["status"]
                    for x in self.session.plugins.run_flow(flow_obj)]

        self.assertEqual(statuses[0].status, "Started")
        self.assertEqual(statuses[1].status, "Done")

        self.assertGreater(statuses[1].timestamp, statuses[0].timestamp)
        self.assertEqual(len(statuses[1].collection_ids), 1)
        self.assertIn(statuses[0].current_action.collection.id,
                      statuses[1].collection_ids)

        with open(os.path.join(self.temp_directory, "collection.json")) as fd:
            collection_data = json.load(fd)
            # Should be two tables, one for data and one for logs
            self.assertEqual(len(collection_data["tables"]), 2)
            self.assertEqual(collection_data["tables"][0]["name"], "logs")
            self.assertEqual(collection_data["tables"][1]["name"], "data")
            self.assertEqual(collection_data["part_number"], 0)

    def XXXtestAgent(self):
        flow = agent.Flow.from_keywords(
            rekall_session=dict(live="API"),
            ticket=dict(
                location=dict(
                    __type__="FileLocation",
                    path_prefix=self.temp_directory,
                    path_template="ticket.json",
                )),
            actions=[
                dict(__type__="CollectAction",
                     query=dict(
                         mode_live_api="select Name, pid from pslist()"
                     ),
                     collection=dict(
                         __type__="JSONCollection",
                         location=dict(
                             __type__="FileLocation",
                             path_prefix=self.temp_directory,
                             path_template="collection.json"),
                         tables=[dict(columns=[
                             dict(
                                 name="Name",
                                 type="unicode"
                             ),
                             dict(
                                 name="pid",
                                 type="int"
                             )
                         ])],
                     ))])

        flow_data = flow.to_primitive()
        for row in self.session.plugins.run_flow(flow_data):
            print row

        print self.temp_directory
        import pdb; pdb.set_trace()

        print self.session.plugins.run_flow(flow.to_primitive())


if __name__ == "__main__":
    testlib.main()
