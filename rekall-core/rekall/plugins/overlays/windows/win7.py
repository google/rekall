# Rekall Memory Forensics
# Copyright (c) 2008-2011 Volatile Systems
# Copyright 2013 Google Inc. All Rights Reserved.
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

"""
@author:       Bradley L Schatz
@license:      GNU General Public License 2.0 or later
@contact:      bradley@schatzforensic.com.au

This file provides support for windows Windows 7 SP 0.
"""

# pylint: disable=protected-access
from rekall import addrspace
from rekall import kb
from rekall import obj
from rekall import utils
from rekall.plugins.overlays.windows import common


def TagOffset(x):
    if x.obj_profile.metadata("arch") == "AMD64":
        return x.obj_offset - 12
    return x.obj_offset - 4

# In windows 7 the VadRoot is actually composed from _MMADDRESS_NODEs instead of
# _MMVAD structs.
win7_overlays = {
    '_EPROCESS': [None, {
        # A symbolic link to the real vad root.
        'RealVadRoot': lambda x: x.VadRoot.BalancedRoot
        }],

    '_MMADDRESS_NODE': [None, {
        'Tag': [TagOffset, ['String', dict(length=4)]],
        }],

    '_MMVAD_SHORT': [None, {
        'Tag': [TagOffset, ['String', dict(length=4)]],
        'Start': lambda x: x.StartingVpn << 12,
        'End': lambda x: ((x.EndingVpn + 1) << 12) - 1,
        'Length': lambda x: x.End - x.Start + 1,
        'CommitCharge': lambda x: x.u.VadFlags.CommitCharge,
        }],

    '_MMVAD': [None, {
        'Tag': [TagOffset, ['String', dict(length=4)]],
        'ControlArea': lambda x: x.Subsection.ControlArea,
        'Start': lambda x: x.StartingVpn << 12,
        'End': lambda x: ((x.EndingVpn + 1) << 12) - 1,
        'Length': lambda x: x.End - x.Start + 1,
        'CommitCharge': lambda x: x.u.VadFlags.CommitCharge,
        }],

    '_MMVAD_LONG': [None, {
        'Tag': [TagOffset, ['String', dict(length=4)]],
        'ControlArea': lambda x: x.Subsection.ControlArea,
        'Start': lambda x: x.StartingVpn << 12,
        'End': lambda x: ((x.EndingVpn + 1) << 12) - 1,
        'Length': lambda x: x.End - x.Start + 1,
        'CommitCharge': lambda x: x.u.VadFlags.CommitCharge,
        }],

    "_CONTROL_AREA": [None, {
        'FilePointer': [None, ['_EX_FAST_REF', dict(
            target="_FILE_OBJECT"
            )]],
        }],

    "_OBJECT_HEADER": [None, {
        "InfoMask": [None, ["Flags", dict(
            maskmap=utils.Invert({
                0x01: "CreatorInfo",
                0x2: "NameInfo",
                0x4: "HandleInfo",
                0x8: "QuotaInfo",
                0x10: "ProcessInfo",
                0x20: "AuditInfo",
                0x40: "PaddingInfo",
                }),
            target="unsigned char",
            )]],
        }],

    '_MM_SESSION_SPACE': [None, {
        # Specialized iterator to produce all the _IMAGE_ENTRY_IN_SESSION
        # records.
        'ImageIterator': lambda x: x.ImageList.list_of_type(
            "_IMAGE_ENTRY_IN_SESSION", "Link")
    }],

    '_IMAGE_ENTRY_IN_SESSION': [None, {
        'ImageBase': lambda x: x.Address.v() & ~7
    }],
}


class _OBJECT_HEADER(common._OBJECT_HEADER):
    """A Rekall Memory Forensics object to handle Windows 7 object headers.

    Windows 7 changes the way objects are handled:
    References: http://www.codemachine.com/article_objectheader.html

    The headers look like this:

    _POOL_HEADER

    # These are optional headers:

    _OBJECT_HEADER_PROCESS_INFO
    _OBJECT_HEADER_QUOTA_INFO
    _OBJECT_HEADER_HANDLE_INFO

    _OBJECT_HEADER:
       .....
       InfoMask
       ....

    When the object manager wants to access a specific optional header, it can
    use the constant lookup table nt!ObpInfoMaskToOffset to quickly calculate
    the offset of that header (The headers always appear in the same order):

    table = profile.get_constant_object(
      "ObpInfoMaskToOffset",
        target="Array",
        target_args=dict(
          target="byte"
          count=0x80
        )
    )

    option_header_offset = table[
       OBJECT_HEADER->InfoMask & (DesiredHeaderBit | (DesiredHeaderBit-1))]
    """

    # This specifies the order the headers are found below the
    # _OBJECT_HEADER. It is obtained using "nt!ObpInfoMaskToOffset" which is a
    # lookup table.
    optional_header_mask = (
        ('CreatorInfo', '_OBJECT_HEADER_CREATOR_INFO', 0x01),
        ('NameInfo', '_OBJECT_HEADER_NAME_INFO', 0x02),
        ('HandleInfo', '_OBJECT_HEADER_HANDLE_INFO', 0x04),
        ('QuotaInfo', '_OBJECT_HEADER_QUOTA_INFO', 0x08),
        ('ProcessInfo', '_OBJECT_HEADER_PROCESS_INFO', 0x10),
        ('AuditInfo', '_OBJECT_HEADER_AUDIT_INFO', 0x20),
        ('PaddingInfo', '_OBJECT_HEADER_PADDING_INFO', 0x40),
        )

    def _GetOptionalHeader(self, struct_name, desired_bit):
        if not self.InfoMask & desired_bit:
            return obj.NoneObject("Header not set")

        lookup = self.obj_session.GetParameter("ObpInfoMaskToOffset")
        offset = lookup[self.InfoMask & (desired_bit | (desired_bit - 1))]
        return self.obj_profile.Object(
            struct_name, offset=self.obj_offset - offset,
            vm=self.obj_vm, parent=self)

    def get_object_type(self, vm=None):
        """Return the object's type as a string."""
        return self.obj_session.GetParameter("ObjectTypeMap")[
            self.TypeIndex].Name.v()

    @utils.safe_property
    def TypeIndex(self):
        """In windows 10 the type index is obfuscated.
        Windows 10 obfuscates the object type using a cookie:

  ------ nt!ObpRemoveObjectRoutine ------: 0xf801a628e7e0
  0xf801a628e7e0 MOV [RSP+0x10], RBX
  0xf801a628e7e5 MOV [RSP+0x18], RBP
  0xf801a628e7ea MOV [RSP+0x20], RSI
  0xf801a628e7ef PUSH RDI
  0xf801a628e7f0 SUB RSP, 0x50
  0xf801a628e7f4 MOV RBX, RCX                   // RCX is object header.
  0xf801a628e7f7 LEA RDI, [RIP-0x48f1e]         0x0 nt!ObTypeIndexTable
  0xf801a628e7fe MOV RAX, RCX
  0xf801a628e801 MOVZX ESI, DL
  0xf801a628e804 SHR RAX, 0x8                   // Shift address by 8
  0xf801a628e808 MOVZX ECX, AL
  0xf801a628e80b MOVZX EAX, BYTE [RBX+0x18]     // _OBJECT_HEADER.TypeIndex
  0xf801a628e80f XOR RCX, RAX                   // XOR with object type
  0xf801a628e812 MOVZX EAX, BYTE [RIP-0x493ed]  0x1dd4015af55 nt!ObHeaderCookie
  0xf801a628e819 XOR RCX, RAX                   // XOR with cookie
  0xf801a628e81c MOV RDI, [RDI+RCX*8]           // Dereference table.
"""
        cookie = self.obj_profile.get_constant_object(
            "ObHeaderCookie", target="byte").v()

        # Windows 7 has no cookie.
        if cookie == None:
            return self.m("TypeIndex")

        # Windows 10 xors the virtual address into this field so we need to use
        # the virtual address to decode it.

        # We are operating on the physical address space. We need to find the
        # virtual address.
        if self.obj_vm.metadata("image"):
            # Resolve the virtual address for this physical address.
            resolver = self.obj_session.GetParameter(
                "physical_address_resolver")

            vaddr, _ = resolver.PA2VA_for_DTB(
                self.obj_offset,
                self.obj_session.GetParameter("dtb"),
                userspace=False)

            # This hit does not exist in the kernel Address Space.
            if vaddr is None:
                return 0
        else:
            vaddr = self.obj_offset

        return ((vaddr >> 8) ^ cookie ^ int(self.m("TypeIndex"))) & 0xFF

    def is_valid(self):
        """Determine if the object makes sense."""
        # These need to be reasonable.
        pointer_count = int(self.PointerCount)
        if pointer_count > 0x100000 or pointer_count < 0:
            return False

        handle_count = int(self.HandleCount)
        if handle_count > 0x1000 or handle_count < 0:
            return False

        # Must be one of the types revealed by the object_types plugins.
        if  self.TypeIndex >= 50 or self.TypeIndex < 1:
            return False

        return True

# Build properties for the optional headers
for _name, _y, _z in _OBJECT_HEADER.optional_header_mask:
    setattr(_OBJECT_HEADER, _name, property(
        lambda x, y=_y, z=_z: x._GetOptionalHeader(y, z)))


class _MMADDRESS_NODE(common.VadTraverser):
    """In win7 the base of all Vad objects is _MMADDRESS_NODE.

    The Vad structures can be either _MMVAD_SHORT or _MMVAD or _MMVAD_LONG. At
    the base of each struct there is an _MMADDRESS_NODE which contains the
    LeftChild and RightChild members. In order to traverse the tree, we follow
    the _MMADDRESS_NODE and create the required _MMVAD type at each point
    depending on their tags.
    """

    ## The actual type depends on this tag value.
    tag_map = {'Vadl': '_MMVAD_LONG',
               'VadS': '_MMVAD_SHORT',
               'Vad ': '_MMVAD',
               'VadF': '_MMVAD_SHORT',
               'Vadm': '_MMVAD_LONG',
              }


class _POOL_HEADER(common._POOL_HEADER):
    """A class for pool headers"""

    MAX_PREAMBLE_SIZE = 0x50

    @utils.safe_property
    def NonPagedPool(self):
        return self.PoolType.v() % 2 == 0 and self.PoolType.v() > 0

    @utils.safe_property
    def PagedPool(self):
        return self.PoolType.v() % 2 == 1

    @utils.safe_property
    def FreePool(self):
        return self.PoolType.v() == 0

    # A class cached version of the lookup map. This is mutable and shared
    # between all instances.
    lookup = {}

    def _BuildLookupTable(self):
        """Create a fast lookup table mapping InfoMask -> minimum_offset.

        We are interested in the maximum distance between the _POOL_HEADER and
        _OBJECT_HEADER. This is dictated by the InfoMask field. Here we build a
        quick lookup table between the InfoMask field and the offset of the
        first optional header.
        """
        ObpInfoMaskToOffset = self.obj_session.GetParameter(
            "ObpInfoMaskToOffset")

        self.lookup["\x00"] = 0

        # Iterate over all the possible InfoMask values (Bytes can take on 256
        # values).
        for i in range(0x100):
            # Locate the largest offset from the start of
            # _OBJECT_HEADER. Starting with the largest bit position 1 << 7.
            bit_position = 0x80
            while bit_position > 0:
                # This is the optional header with the largest offset.
                if bit_position & i:
                    self.lookup[chr(i)] = ObpInfoMaskToOffset[
                        i & (bit_position | (bit_position - 1))]

                    break
                bit_position >>= 1

    def IterObject(self, type=None, freed=True):
        """Generates possible _OBJECT_HEADER accounting for optional headers.

        Note that not all pool allocations have an _OBJECT_HEADER - only ones
        allocated from the the object manager. This means calling this method
        depends on which pool allocation you are after.

        On windows 8, pool allocations are done from preset sizes. This means
        that the allocation is never exactly the same size and we can not use
        the bottom up method like before.

        We therefore, have to build the headers forward by checking the preamble
        size and validity of each object. This is a little slower than with
        earlier versions of windows.

        Args:
          type: The object type name. If not specified we return all objects.
        """
        pool_align = self.obj_profile.get_constant("PoolAlignment")
        allocation_size = self.BlockSize * pool_align

        # Operate on a cached version of the next page.
        # We use a temporary buffer for the object to save reads of the image.
        start = self.obj_end
        cached_data = self.obj_vm.read(start, allocation_size)
        cached_vm = addrspace.BufferAddressSpace(
            base_offset=start, data=cached_data, session=self.obj_session)

        # We search for the _OBJECT_HEADER.InfoMask in close proximity to our
        # object. We build a lookup table between the values in the InfoMask and
        # the minimum distance there is between the start of _OBJECT_HEADER and
        # the end of _POOL_HEADER. This way we can quickly skip unreasonable
        # values.

        # This is the offset within _OBJECT_HEADER of InfoMask.
        info_mask_offset = self.obj_profile.get_obj_offset(
            "_OBJECT_HEADER", "InfoMask")

        # Build the cache if needed.
        if not self.lookup:
            self._BuildLookupTable()

        # Walk over all positions in the address space and try to fit an object
        # header there.
        for i in utils.xrange(start,
                              start + allocation_size - info_mask_offset,
                              pool_align):
            possible_info_mask = cached_data[i - start + info_mask_offset]
            #if possible_info_mask > '\x7f':
            #    continue

            # The minimum amount of space needed before the object header to
            # hold all the optional headers.
            minimum_offset = self.lookup[possible_info_mask]

            # Obviously wrong because we need more space than we have.
            if minimum_offset > i - start:
                continue

            # Create a test object header from the cached vm to test for
            # validity.
            test_object = self.obj_profile._OBJECT_HEADER(
                offset=i, vm=cached_vm)

            if test_object.is_valid():
                if (type is None or
                        test_object.get_object_type() == type or
                        # Freed objects point to index 1
                        #(which is also 0xbad0b0b0).
                        (freed and test_object.TypeIndex <= 2)):
                    yield test_object


class ObjectTypeMapHook(kb.ParameterHook):
    """Get and cache the object type map.

    In windows 7, rather than store a pointer to the _OBJECT_TYPE object
    directly, there is a global table of object types, and the object simply
    stores an index to it.
    """
    name = "ObjectTypeMap"

    def calculate(self):
        return self.session.profile.get_constant_object(
            "ObTypeIndexTable",
            target="Array",
            target_args=dict(
                target="Pointer",
                target_args=dict(
                    target="_OBJECT_TYPE"
                    )
                )
            )


def InitializeWindows7Profile(profile):
    profile.add_overlay(win7_overlays)
    profile.add_classes(
        _OBJECT_HEADER=_OBJECT_HEADER,
        _MMADDRESS_NODE=_MMADDRESS_NODE,
        _POOL_HEADER=_POOL_HEADER,
        )
