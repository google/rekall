# Rekall Memory Forensics
# Copyright (c) 2008-2011 Volatile Systems
# Copyright 2013 Google Inc. All Rights Reserved.

# Author: Michael Cohen <scudette@gmail.com>
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

# pylint: disable=protected-access
from rekall import addrspace
from rekall import kb
from rekall.plugins.overlays.windows import common
from rekall.plugins.overlays.windows import win7

def TagOffset(x):
    if x.obj_profile.metadata("arch") == "AMD64":
        return x.obj_offset - 12
    return x.obj_offset - 4

# In windows 8 the VadRoot is actually composed from _MM_AVL_NODE instead of
# _MMVAD structs or _MMADDRESS_NODE. The structs appear to be organised by
# functional order - the _MM_AVL_NODE is always the first member of the struct,
# then the _MMVAD_SHORT, then the _MMVAD. For example, the tree traversal code,
# simply casts all objects to an _MM_AVL_NODE without caring what they actually
# are, then depending on the vad tag, they get casted to different structs.
win8_overlays = {
    '_EPROCESS': [None, {
        # A symbolic link to the real vad root.
        'RealVadRoot': lambda x: x.VadRoot.BalancedRoot
        }],

    '_MM_AVL_NODE': [None, {
            'Tag': [TagOffset, ['String', dict(length=4)]],
            }],

    '_RTL_BALANCED_NODE': [None, {
            'Tag': [TagOffset, ['String', dict(length=4)]],
            }],

    '_MMVAD_SHORT': [None, {
            'Tag': [TagOffset, ['String', dict(length=4)]],
            'Start': lambda x: x.StartingVpn << 12,
            'End': lambda x: ((x.EndingVpn + 1) << 12) - 1,
            'CommitCharge': lambda x: x.u1.VadFlags1.CommitCharge,
            }],

    '_MMVAD': [None, {
            'Tag': [TagOffset, ['String', dict(length=4)]],
            'ControlArea': lambda x: x.Subsection.ControlArea,
            'Start': lambda x: x.Core.StartingVpn << 12,
            'End': lambda x: ((x.Core.EndingVpn + 1) << 12) - 1,
            'Length': lambda x: x.End - x.Start + 1,
            'CommitCharge': lambda x: x.Core.u1.VadFlags1.CommitCharge,
            'u': lambda x: x.Core.u,
            }],

    '_MMVAD_LONG': [None, {
            'Tag': [TagOffset, ['String', dict(length=4)]],
            'ControlArea': lambda x: x.Subsection.ControlArea,
            'Start': lambda x: x.Core.StartingVpn << 12,
            'End': lambda x: ((x.Core.EndingVpn + 1) << 12) - 1,
            'Length': lambda x: x.End - x.Start + 1,
            'CommitCharge': lambda x: x.Core.u.VadFlags.CommitCharge,
            'u': lambda x: x.Core.u,
            }],

    "_CONTROL_AREA": [None, {
        'FilePointer': [None, ['_EX_FAST_REF', dict(
            target="_FILE_OBJECT"
            )]],
        }],

    '_HANDLE_TABLE_ENTRY' : [None, {
        # In Windows 8 the Object pointer is replaced with a bitfield.
        'Object': lambda x: x.obj_profile.Pointer(
            target="_OBJECT_HEADER",
            value=(x.ObjectPointerBits << 4 | 0xFFFFE00000000000),
            vm=x.obj_vm, parent=x)
        }],

    '_OBJECT_HEADER': [None, {
        'GrantedAccess': lambda x: x.obj_parent.GrantedAccessBits
        }],
    }

win8_1_overlays = {
    '_EPROCESS': [None, {
        # A symbolic link to the real vad root.
        'RealVadRoot': lambda x: x.VadRoot.Root
        }],
    }


class ObpInfoMaskToOffsetHook(kb.ParameterHook):
    """By caching this map we can speed up lookups significantly."""

    name = "ObpInfoMaskToOffset"

    def calculate(self):
        table_offset = self.session.profile.get_constant(
            "ObpInfoMaskToOffset", True)

        # We use a temporary buffer for the object to save reads of the image.
        cached_vm = addrspace.BufferAddressSpace(
            data=self.session.kernel_address_space.read(table_offset, 0x100),
            session=self.session)

        return [int(x) for x in self.session.profile.Array(
            target="byte", vm=cached_vm, count=0xFF)]


class _PSP_CID_TABLE(common._HANDLE_TABLE):
    """Subclass the Windows handle table object for parsing PspCidTable"""

    def get_item(self, entry):
        p = entry.Object.v()

        handle = self.obj_profile.Object(
            "_OBJECT_HEADER",
            offset=(p & ~7) - self.obj_profile.get_obj_offset(
                '_OBJECT_HEADER', 'Body'),
            vm=self.obj_vm)

        return handle


class _POOL_HEADER(common._POOL_HEADER):
    """A class for pool headers"""

    MAX_PREAMBLE_SIZE = 0x50

    @property
    def NonPagedPool(self):
        return self.PoolType.v() % 2 == 0 and self.PoolType.v() > 0

    @property
    def PagedPool(self):
        return self.PoolType.v() % 2 == 1

    @property
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

        # Iterate over all the possible InfoMask values.
        for i in range(0x80):
            # Locate the largest offset from the start of _OBJECT_HEADER.
            bit_position = 0x40
            while bit_position > 0:
                # This is the optional header with the largest offset.
                if bit_position & i:
                    self.lookup[chr(i)] = ObpInfoMaskToOffset[
                        i & (bit_position | (bit_position - 1))]

                    break
                bit_position >>= 1

    def IterObject(self, type=None):
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
        cached_data = self.obj_vm.read(self.obj_offset + self.size(),
                                       allocation_size)
        cached_vm = addrspace.BufferAddressSpace(
            data=cached_data, session=self.obj_session)

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

        for i in range(0, allocation_size - info_mask_offset, pool_align):
            possible_info_mask = cached_data[i + info_mask_offset]
            if possible_info_mask > '\x7f':
                continue

            minimum_offset = self.lookup[possible_info_mask]

            # Obviously wrong because we need more space than we have.
            if minimum_offset > i:
                continue

            # Create a test object header from the cached vm to test for
            # validity.
            test_object = self.obj_profile._OBJECT_HEADER(
                offset=i, vm=cached_vm)

            if test_object.is_valid():
                if type is not None and test_object.get_object_type() != type:
                    continue

                yield self.obj_profile._OBJECT_HEADER(
                    offset=i + self.obj_offset + self.size(),
                    vm=self.obj_vm, parent=self)


class _MM_AVL_NODE(common.VadTraverser):
    """All nodes in the Vad tree are treated as _MM_AVL_NODE.

    The Vad structures can be either _MMVAD_SHORT or _MMVAD. At the
    base of each struct there is an _MM_AVL_NODE which contains the LeftChild
    and RightChild members. In order to traverse the tree, we follow the
    _MM_AVL_NODE and create the required _MMVAD type at each point.

    In Windows 8 these behave the same as windows 7's _MMADDRESS_NODE.
    """

    ## The actual type depends on this tag value. Windows 8 does not have an
    ## _MMVAD_LONG.
    tag_map = {'Vadl': '_MMVAD',
               'VadS': '_MMVAD_SHORT',
               'Vad ': '_MMVAD',
               'VadF': '_MMVAD_SHORT',
               'Vadm': '_MMVAD',
              }


class _RTL_BALANCED_NODE(_MM_AVL_NODE):
    """Win8.1 renames this type."""
    left = "Left"
    right = "Right"


def InitializeWindows8Profile(profile):
    """Initialize windows 8 and 8.1 profiles."""
    profile.add_overlay(win8_overlays)

    # Win8.1 changed the vad data structures.
    if profile.metadata("version") >= "6.3":
        profile.add_overlay(win8_1_overlays)

    profile.add_classes(dict(
        _OBJECT_HEADER=win7._OBJECT_HEADER,
        _PSP_CID_TABLE=_PSP_CID_TABLE,
        _MM_AVL_NODE=_MM_AVL_NODE,
        _RTL_BALANCED_NODE=_RTL_BALANCED_NODE,
        ))

    # Windows 8 changes many of the pool tags. These come from windbg's
    # pooltag.txt.
    profile.add_constants(
        DRIVER_POOLTAG="Driv",
        EPROCESS_POOLTAG="Proc",
        FILE_POOLTAG="File",
        SYMLINK_POOLTAG="Symb",
        MODULE_POOLTAG="MmLd",
        MUTANT_POOLTAG="Muta",
        THREAD_POOLTAG='Thre',
        )

    profile.add_classes(dict(_POOL_HEADER=_POOL_HEADER))
