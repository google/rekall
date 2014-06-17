# Rekall Memory Forensics
# Copyright 2014 Google Inc. All Rights Reserved.
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

"""Tests for json encoding/decoding."""
import json
import logging

from rekall import session
from rekall import testlib
from rekall.ui import json_renderer


class JsonTest(testlib.RekallBaseUnitTestCase):
    """Test the Json encode/decoder."""
    PLUGIN = "json_render"

    def testProperSerialization(self):
        self.session = session.Session()
        self.encoder = json_renderer.JsonEncoder()
        self.decoder = json_renderer.JsonDecoder(self.session)

        for case in [
            [1, 2],
            [1, "hello"],
            ["1", "2"],
            ["hello", u'Gr\xfcetzi'],
            "hello",
            u'Gr\xfcetzi',
            dict(a="hello"),
            dict(b=dict(a="hello")),
            {1: 2}
            ]:
            self.encoder.flush()
            data = self.encoder.Encode(case)
            logging.debug("%s->%s" % (case, data))

            # Make sure the data is JSON serializable.
            self.assertEqual(data, json.loads(json.dumps(data)))

            self.decoder.SetLexicon(self.encoder.GetLexicon())
            self.assertEqual(case, self.decoder.Decode(data))

    def testObjectSerization(self):
        """Serialize _EPROCESS objects.

        We check that the deserialized object is an exact replica of the
        original - this includes the same address spaces, profile and offset.

        Having the objects identical allows us to dereference object members
        seamlessly.
        """
        self.session = self.MakeUserSession()
        self.encoder = json_renderer.JsonEncoder()
        self.decoder = json_renderer.JsonDecoder(self.session)

        for task in self.session.plugins.pslist().filter_processes():
            self.encoder.flush()
            data = self.encoder.Encode(task)
            logging.debug("%r->%s" % (task, data))

            # Make sure the data is JSON serializable.
            self.assertEqual(data, json.loads(json.dumps(data)))

            self.decoder.SetLexicon(self.encoder.GetLexicon())
            decoded_task = self.decoder.Decode(data)
            self.assertEqual(task.obj_offset, decoded_task.obj_offset)
            self.assertEqual(task.obj_name, decoded_task.obj_name)
            self.assertEqual(task.obj_vm.name, decoded_task.obj_vm.name)

            # Check the process name is the same - this tests subfield
            # dereferencing.
            self.assertEqual(task.name, decoded_task.name)
            self.assertEqual(task.pid, decoded_task.pid)
