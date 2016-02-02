# Rekall Memory Forensics
# Copyright 2013 Google Inc. All Rights Reserved.
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
import gzip
import os

from rekall import constants
from rekall import io_manager
from rekall import testlib


class IOManagerTest(testlib.RekallBaseUnitTestCase):
    """Test the IO Manager."""

    DATA = {
        "foo.gz": "hello",
        "bar": "goodbye"
    }

    def setUp(self):
        super(IOManagerTest, self).setUp()

        # Create a new repository in the temp directory.
        self.version = constants.PROFILE_REPOSITORY_VERSION
        for filename, data in self.DATA.iteritems():
            path = os.path.join(self.temp_directory, self.version,
                                filename)

            if path.endswith("gz"):
                opener = gzip.open
            else:
                opener = open

            try:
                os.makedirs(os.path.dirname(path))
            except (OSError, IOError):
                pass

            with opener(path, "wb") as fd:

                fd.write(data)

    def testDirectoryIOManager(self):
        manager = io_manager.DirectoryIOManager(
            self.temp_directory,
            session=self.MakeUserSession())

        # Cant decode from json.
        self.assertEqual(manager.GetData("foo"), None)
        self.assertEqual(manager.GetData("foo", raw=True),
                         "hello")

        # Test ListFiles().
        self.assertListEqual(sorted(manager.ListFiles()),
                             ["bar", "foo"])

        # Storing a data structure.
        data = dict(a=1)
        manager.StoreData("baz", data)
        self.assertDictEqual(manager.GetData("baz"),
                             data)

        self.assertTrue(
            isinstance(manager.GetData("baz", raw=True), basestring))
