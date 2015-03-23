# Rekall Memory Forensics
#
# Copyright 2015 Google Inc. All Rights Reserved.
#
# Authors:
# Copyright (C) 2015 Michael Cohen <scudette@google.com>
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

"""This Address Space allows us to open aff4 images.

AFF4 images are produced by the Rekall memory acquisition tools (Pmem and
friends).

For this address space to work:

pip install pyaff4

"""
import logging
import os

from rekall import addrspace
from rekall.plugins.addrspaces import standard

from pyaff4 import data_store
from pyaff4 import zip
from pyaff4 import lexicon
from pyaff4 import rdfvalue

from pyaff4 import plugins  # pylint: disable=unused-import


# Control the logging level for the pyaff4 library logger.
LOGGER = logging.getLogger("pyaff4")
LOGGER.setLevel(logging.ERROR)


class AFF4StreamWrapper(object):
    def __init__(self, stream):
        self.stream = stream

    def read(self, offset, length):
        self.stream.seek(offset)
        return self.stream.read(length)

    def end(self):
        return self.stream.Size()


class AFF4AddressSpace(addrspace.CachingAddressSpaceMixIn,
                       addrspace.MultiRunBasedAddressSpace):
    """Handle AFF4Map or AFF4Image type streams.

    Since AFF4 volumes may contain multiple streams, we allow the stream to be
    specified inside the volume path. For example suppose the volume located at:

    /home/mic/images/myimage.aff4

    Contains a stream called PhysicalMemory, then we can specify the filename
    as:

    /home/mic/images/myimage.aff4/PhysicalMemory

    If we just specified the path to the volume, then this address space will
    pick the first AFF4 stream which has an aff4:category of
    lexicon.AFF4_MEMORY_PHYSICAL.

    So if you have more than one physical memory stream in the same volume, you
    will need to specify the full path to the stream within the volume.
    """
    __name = "aff4"
    __image = True

    order = standard.FileAddressSpace.order - 10

    def __init__(self, filename=None, **kwargs):
        super(AFF4AddressSpace, self).__init__(**kwargs)

        self.as_assert(self.base == None,
                       "Must stack on another address space")

        path = filename or self.session.GetParameter("filename")
        self.as_assert(path != None, "Filename must be specified")

        self.image = None
        self.phys_base = self
        self.resolver = data_store.MemoryDataStore()

        try:
            volume_path, stream_path = self._LocateAFF4Volume(path)
        except IOError:
            raise addrspace.ASAssertionError("Unable to open AFF4 volume")

        # filename is a volume, and there is no stream specified, just autoload
        # the stream if possible.
        if not stream_path:
            try:
                self._AutoLoadAFF4Volume(volume_path)
                return
            except IOError:
                raise addrspace.ASAssertionError("Unable to open AFF4 volume")

        # If the user asked for a specific stream just load that one. Note that
        # you can still load the pagefile manually using the --pagefile
        # parameter.
        with zip.ZipFile.NewZipFile(self.resolver, volume_path) as volume:
            self._LoadMemoryImage(volume.urn.Append(stream_path))

    def _LocateAFF4Volume(self, filename):
        stream_name = []
        volume_path = filename
        while volume_path:
            try:
                volume_urn = rdfvalue.URN.FromFileName(volume_path)
                with self.resolver.AFF4FactoryOpen(volume_urn) as aff4_stream:
                    if stream_name:
                        return aff4_stream.urn, os.path.join(*stream_name)

                    return aff4_stream.urn, None

            except IOError:
                volume_path, stream_component = os.path.split(volume_path)
                if not stream_component:
                    break

                stream_name.insert(0, stream_component)

        raise IOError("Not found")

    def _AutoLoadAFF4Volume(self, path):
        with zip.ZipFile.NewZipFile(self.resolver, path):
            # We are searching for images with the physical memory category.
            for (subject, _, value) in self.resolver.QueryPredicate(
                    lexicon.AFF4_CATEGORY):
                if value == lexicon.AFF4_MEMORY_PHYSICAL:
                    self._LoadMemoryImage(subject)
                    break

        self.as_assert(self.image is not None,
                       "No physical memory categories found.")

        # Attempt to load any page files if there are any.
        for (subject, _, value) in self.resolver.QueryPredicate(
                lexicon.AFF4_CATEGORY):
            if value == lexicon.AFF4_MEMORY_PAGEFILE:
                pagefile_stream = self.resolver.AFF4FactoryOpen(subject)

                self.pagefile_offset = self.end() + 0x10000
                self.pagefile_end = (
                    self.pagefile_offset + pagefile_stream.Size())

                self.add_run(
                    self.pagefile_offset, 0, pagefile_stream.Size(),
                    AFF4StreamWrapper(pagefile_stream))

                logging.info(
                    "Added %s as pagefile", subject)

    def _LoadMemoryImage(self, image_urn):
        aff4_stream = self.resolver.AFF4FactoryOpen(image_urn)
        self.image = AFF4StreamWrapper(aff4_stream)

        # Add the ranges if this is a map.
        try:
            for map_range in aff4_stream.GetRanges():
                self.runs.insert((map_range.map_offset,
                                  map_range.map_offset,
                                  map_range.length,
                                  self.image))
        except AttributeError:
            self.runs.insert((0, 0, aff4_stream.Size(), self.image))

        logging.info("Added %s as physical memory", image_urn)
