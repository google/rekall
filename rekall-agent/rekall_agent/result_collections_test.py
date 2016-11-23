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
from rekall_agent import result_collections
from rekall_agent.locations import files


class TestResultCollection(testlib.RekallBaseUnitTestCase):

    def setUp(self):
        self.session = self.MakeUserSession()

    def _make_collection(self):
        # The path where we want the collection to finally reside.
        final_path = os.path.join(self.temp_directory, "test.sqlite")

        # Make a SQL Collection.
        collection = result_collections.GenericSQLiteCollection.from_keywords(
            session=self.session,
            # Store the file locally.
            location=files.FileLocation.from_keywords(
                session=self.session,
                path_prefix=final_path),
            tables=[dict(name="default",
                         columns=[dict(name="c1", type="int"),
                                  dict(name="c2", type="unicode"),
                                  dict(name="c3", type="float")])],
        )

        return collection, final_path

    def testCollectionAction(self):
        collection, final_path = self._make_collection()

        with collection.create_temp_file():
            self.assertFalse(os.access(final_path, os.R_OK))
            self.assertTrue(os.access(collection._filename, os.R_OK))

            # Insert some data.
            collection.insert(c1=5, c2="foobar", c3=1.1)

        # Make sure the tempfile is removed and the final_path exists.
        self.assertFalse(os.access(collection._filename, os.R_OK))
        self.assertTrue(os.access(final_path, os.R_OK))

        # Re-open the collection for reading.
        with result_collections.GenericSQLiteCollection.load_from_location(
                collection.location, session=self.session) as read_collection:
            # This should reuse the final_path saving a local copy.
            self.assertEqual(read_collection._filename, final_path)

            # Query the collection.
            self.assertEqual([tuple(x) for x in read_collection.query()],
                             [(5, "foobar", 1.1)])


if __name__ == "__main__":
    testlib.main()
