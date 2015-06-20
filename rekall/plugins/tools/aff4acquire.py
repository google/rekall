# Rekall Memory Forensics
#
# Copyright 2015 Google Inc. All Rights Reserved.
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

"""This plugin adds the ability for Rekall to acquire an AFF4 image.

It is an alternative to the pmem suite of acquisition tools, which also creates
AFF4 images. The difference being that this plugin will apply live analysis to
acquire more relevant information (e.g. mapped files etc).
"""

__author__ = "Michael Cohen <scudette@google.com>"

import time

from rekall import plugin
from rekall import testlib

from pyaff4 import data_store
from pyaff4 import aff4_image
from pyaff4 import aff4_map
from pyaff4 import zip
from pyaff4 import lexicon
from pyaff4 import rdfvalue

from pyaff4 import plugins  # pylint: disable=unused-import


class AFF4Acquire(plugin.PhysicalASMixin, plugin.Command):
    """Copy the physical address space to an AFF4 file."""

    name = "aff4acquire"

    BUFFERSIZE = 1024 * 1024

    @classmethod
    def args(cls, parser):
        super(AFF4Acquire, cls).args(parser)

        parser.add_argument(
            "destination", default="output.aff4", required=False,
            help="The destination file to create. "
            "If not specified we write output.aff4 in current directory.")

        parser.add_argument(
            "--compression", default="zlib", required=False,
            choices=["snappy", "stored", "zlib"],
            help="The compression to use.")

    def __init__(self, destination=None, compression=None, **kwargs):
        super(AFF4Acquire, self).__init__(**kwargs)

        self.destination = destination or "output.aff4"
        if compression == "snappy" and aff4_image.snappy:
            compression = lexicon.AFF4_IMAGE_COMPRESSION_SNAPPY
        elif compression == "stored":
            compression = lexicon.AFF4_IMAGE_COMPRESSION_STORED
        elif compression == "zlib":
            compression = lexicon.AFF4_IMAGE_COMPRESSION_ZLIB
        else:
            raise plugin.PluginError(
                "Compression scheme not supported.")

        self.compression = compression

    def copy_physical_address_space(self, resolver, volume):
        """Copies the physical address space to the output volume."""
        image_urn = volume.urn.Append("PhysicalMemory")
        source = self.physical_address_space

        if self.compression:
            storage_urn = image_urn.Append("data")
            resolver.Set(storage_urn, lexicon.AFF4_IMAGE_COMPRESSION,
                         rdfvalue.URN(self.compression))

        with aff4_map.AFF4Map.NewAFF4Map(
            resolver, image_urn, volume.urn) as image_stream:

            # Mark the stream as a physical memory stream.
            resolver.Set(image_stream.urn, lexicon.AFF4_CATEGORY,
                         rdfvalue.URN(lexicon.AFF4_MEMORY_PHYSICAL))

            total = 0
            last_tick = time.time()

            for offset, _, length in source.get_address_ranges():
                image_stream.seek(offset)

                while length > 0:
                    to_read = min(length, self.BUFFERSIZE)
                    data = source.read(offset, to_read)

                    image_stream.write(data)
                    now = time.time()

                    read_len = len(data)
                    if now > last_tick:
                        rate = read_len / (now - last_tick) / 1e6
                    else:
                        rate = 0

                    self.session.report_progress(
                        "Wrote %#x (%d total) (%02.2d Mb/s)", offset,
                        total / 1e6, rate)

                    length -= read_len
                    offset += read_len
                    total += read_len
                    last_tick = now

    def render(self, renderer):
        with renderer.open(filename=self.destination, mode="w+b") as out_fd:
            with data_store.MemoryDataStore() as resolver:
                output_urn = rdfvalue.URN.FromFileName(out_fd.name)
                resolver.Set(output_urn, lexicon.AFF4_STREAM_WRITE_MODE,
                             rdfvalue.XSDString("truncate"))

                with zip.ZipFile.NewZipFile(resolver, output_urn) as volume:
                    self.copy_physical_address_space(resolver, volume)


# We can not check the file hash because AFF4 files contain UUID which will
# change each time.
class TestAFF4Acquire(testlib.SimpleTestCase):
    PARAMETERS = dict(commandline="aff4acquire %(tempdir)s/output_image.aff4")
