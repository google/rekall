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

from rekall import testlib
from rekall.ui import json_renderer


class JsonTest(testlib.RekallBaseUnitTestCase):
    """Test the Json encode/decoder."""
    PLUGIN = "json_render"

    def setUp(self):
        self.session = self.MakeUserSession()
        self.renderer = json_renderer.JsonRenderer(session=self.session)
        self.encoder = self.renderer.encoder
        self.decoder = self.renderer.decoder

    def testObjectRenderer(self):
        cases = [
            ('\xff\xff\x00\x00', {'mro': u'str:basestring:object',
                                  'b64': u'//8AAA=='}),

            ("hello", u'hello'),  # A string is converted into unicode if
                                  # possible.

            (1, 1),     # Ints are already JSON serializable.
            (dict(foo=2), {'foo': 2}),
            (set([1, 2, 3]), {'mro': u'set:object', 'data': [1, 2, 3]}),
            ([1, 2, 3], [1, 2, 3]),

            ([1, "\xff\xff\x00\x00", 3], [1, {'mro': u'str:basestring:object',
                                              'b64': u'//8AAA=='}, 3]),

            ]

        for case in cases:
            encoded = self.encoder.Encode(case[0])
            self.assertEqual(encoded, case[1])

    def testProperSerialization(self):
        """Test that serializing simple python objects with json works.

        NOTE: Json is not intrinsically a fully functional serialization format
        - it is unable to serialize many common python primitives (e.g. strings,
        dicts with numeric keys etc). This tests that our wrapping around the
        json format allows the correct serialization of python primitives.
        """
        for case in [
                [1, 2],
                [1, "hello"],
                ["1", "2"],
                ["hello", u'Gr\xfcetzi'],
                "hello",
                u'Gr\xfcetzi',
                dict(a="hello"),
                dict(b=dict(a="hello")), # Nested dict.
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

    def testAllObjectSerialization(self):
        for vtype in self.session.profile.vtypes:
            obj = self.session.profile.Object(vtype)
            self.CheckObjectSerization(obj)

        self.CheckObjectSerization(self.session)
        self.CheckObjectSerization(self.session.profile)
        self.CheckObjectSerization(self.session.kernel_address_space)
        self.CheckObjectSerization(self.session.physical_address_space)

        # Some native types.
        self.CheckObjectSerization(set([1, 2, 3]))
        self.CheckObjectSerization(dict(a=1, b=dict(a=1)))

    def CheckObjectSerization(self, obj):
        object_renderer_cls = json_renderer.JsonObjectRenderer.ForTarget(
            obj, "JsonRenderer")

        object_renderer = object_renderer_cls(session=self.session,
                                              renderer="JsonRenderer")

        encoded = object_renderer.EncodeToJsonSafe(obj, strict=True)

        # Make sure it is json safe.
        json.dumps(encoded)

        # Now decode it.
        decoding_object_renderer_cls = json_renderer.JsonObjectRenderer.FromEncoded(
            encoded, "JsonRenderer")

        self.assertEqual(decoding_object_renderer_cls, object_renderer_cls)
        decoded = object_renderer.DecodeFromJsonSafe(encoded, {})
        self.assertEqual(decoded, obj)

        # Now check the DataExportRenderer.
        object_renderer_cls = json_renderer.JsonObjectRenderer.ForTarget(
            obj, "DataExportRenderer")


        object_renderer = object_renderer_cls(session=self.session,
                                              renderer="DataExportRenderer")

        encoded = object_renderer.EncodeToJsonSafe(obj, strict=True)

        # Make sure it is json safe.
        json.dumps(encoded)

        # Data Export is not decodable.
