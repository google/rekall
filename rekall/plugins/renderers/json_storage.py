# Rekall Memory Forensics
# Copyright 2014 Google Inc. All Rights Reserved.
#
# Authors:
# Michael Cohen <scudette@google.com>
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

"""This file implements ObjectRenderers for the JsonRenderer.

The JsonRenderer aims to serialize and recreate objects exactly at they were
upon unserializing them. This means that the environment loading the serialized
data must have access to all the necessary files (i.e. the complete memory image
file).

For example consider an _EPROCESS() instance. In memory, python merely stores
the following items in the object:

- obj_offset: The offset in the address space.
- obj_profile: The profile this object came from.
- obj_vm: The address space the object will be read from.

When the object is read, the address space is read at obj_offset, the data is
decoded and possibly other members are created using the profile. We do not know
the value of the object without reading it from the image.

Contrast this with the WebConsoleRenderer which needs to be deserialized in an
environment which does not have access to the original image. In this case we
must store all kinds of additional metadata about each object, since the decoder
is unable to directly get this information.

Example:

zeus2x4.vmem.E01 23:46:28> x = session.profile._EPROCESS(0x81e8a368)
zeus2x4.vmem.E01 23:46:32> encoder = json_renderer.JsonEncoder()
zeus2x4.vmem.E01 23:46:34> print encoder.Encode(x)
{'offset': 2179507048,
 'profile': ('*', u'nt/GUID/1B2D0DFE2FB942758D615C901BE046922'),
 'type': u'_EPROCESS,_EPROCESS,Struct,BaseAddressComparisonMixIn,BaseObject',
 'type_name': ('*', u'_EPROCESS'),
 'vm': {'base': {'filename': ('*',
    u'/home/scudette/images/zeus2x4.vmem.E01'),
   'type': u'EWFAddressSpace,CachingAddressSpaceMixIn,FDAddressSpace,BaseAddressSpace'},
  'dtb': 233472,
  'type': u'IA32PagedMemory,PagedReader,BaseAddressSpace'}}

zeus2x4.vmem.E01 23:47:25> decoder = json_renderer.JsonDecoder(session=session)
zeus2x4.vmem.E01 23:48:10> print decoder.Decode(encoder.Encode(x)).ImageFileName
alg.exe

Since the decoder is able to exactly recreate the original object, this object
can then be subsequently used to dereference the memory image - we can recover
the _EPROCESS.ImageFileName attribute and print the process name - even though
the actual name was never encoded.
"""

from rekall import obj
from rekall import session
from rekall import utils
from rekall.ui import json_renderer


class FileAddressSpaceObjectRenderer(
    json_renderer.BaseAddressSpaceObjectRenderer):
    renders_type = "FileAddressSpace"

    def GetState(self, item, **options):
        state = super(FileAddressSpaceObjectRenderer, self).GetState(
            item, **options)
        state["filename"] = item.name

        return state


class EWFAddressSpaceObjectRenderer(FileAddressSpaceObjectRenderer):
    renders_type = "EWFAddressSpace"


class AttributeDictObjectRenderer(json_renderer.StateBasedObjectRenderer):
    renders_type = "AttributeDict"

    def GetState(self, item, **_):
        return dict(data=dict(item))

    def DecodeFromJsonSafe(self, state, options):
        state = super(AttributeDictObjectRenderer, self).DecodeFromJsonSafe(
            state, options)

        return utils.AttributeDict(state.get("data", {}))


class IA32PagedMemoryObjectRenderer(
    json_renderer.BaseAddressSpaceObjectRenderer):
    renders_type = "IA32PagedMemory"

    def GetState(self, item, **options):
        state = super(IA32PagedMemoryObjectRenderer, self).GetState(
            item, **options)
        state["dtb"] = item.dtb

        return state


class SessionObjectRenderer(json_renderer.StateBasedObjectRenderer):
    renders_type = "Session"

    def GetState(self, item, **_):
        result = dict(item.state)
        result["cls"] = item.__class__.__name__
        return result

    def DecodeFromJsonSafe(self, state, options):
        state = super(SessionObjectRenderer, self).DecodeFromJsonSafe(
            state, options)

        cls_name = state.pop("cls")
        result = session.Session.classes[cls_name]()
        with result:
            for k, v in state.iteritems():
                result.SetParameter(k, v)

        return result


class ProfileObjectRenderer(json_renderer.StateBasedObjectRenderer):
    renders_type = "Profile"

    def GetState(self, item, **_):
        return dict(name=item.name)

    def DecodeFromJsonSafe(self, state, options):
        state = super(ProfileObjectRenderer, self).DecodeFromJsonSafe(
            state, options)

        return self.session.LoadProfile(state["name"])


class SetObjectRenderer(json_renderer.StateBasedObjectRenderer):
    """Encode a python set()."""
    renders_type = "set"

    def GetState(self, item, **_):
        return dict(data=list(item))

    def DecodeFromJsonSafe(self, state, options):
        return set(state["data"])


class NoneObjectRenderer(json_renderer.StateBasedObjectRenderer):
    """Encode a None Object."""
    renders_type = "NoneObject"

    def GetState(self, item, **_):
        return dict(reason=item.FormatReason())

    def DecodeFromJsonSafe(self, state, options):
        return obj.NoneObject(state.get("reason"))


class PointerObjectRenderer(json_renderer.StateBasedObjectRenderer):
    """Encode a Pointer."""
    renders_type = "Pointer"

    def GetState(self, item, **options):
        state = super(PointerObjectRenderer, self).GetState(item, **options)
        state["target"] = self.target
        state["target_args"] = self.target_args

        return state


class ArrayObjectRenderer(PointerObjectRenderer):
    renders_type = "Array"

    def GetState(self, item, **options):
        state = super(ArrayObjectRenderer, self).GetState(item, **options)
        state["count"] = self.count

        return state
