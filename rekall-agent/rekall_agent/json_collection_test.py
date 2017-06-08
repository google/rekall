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
import os

from rekall import testlib
from rekall_agent import json_collection
from rekall_agent.locations import files


class TestJSONCollection(testlib.RekallBaseUnitTestCase):
    def setUp(self):
        self.session = self.MakeUserSession()

    def _make_collection(self):
        # Make a SQL Collection.
        collection = json_collection.JSONCollection.from_keywords(
            session=self.session,
            # Store the file locally.
            location=files.FileLocationImpl.from_keywords(
                session=self.session,
                path_prefix=self.temp_directory,
                path_template="test_{part}.json"),
            max_rows=10,
            tables=[dict(name="default",
                         columns=[dict(name="c1", type="int"),
                                  dict(name="c2", type="unicode"),
                                  dict(name="c3", type="float")])],
        )

        return collection

    def testJSONCollection(self):
        collection = self._make_collection()
        with collection:
            for i in range(100):
                # Insert some data.
                collection.insert(c1=5 * i, c2="foobar%s" % i, c3=1.1 + i)

        listed_files = os.listdir(self.temp_directory)
        self.assertEqual(len(listed_files), 10)


if __name__ == "__main__":
    testlib.main()
