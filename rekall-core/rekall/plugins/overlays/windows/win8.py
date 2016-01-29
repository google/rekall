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
from rekall import obj
from rekall import utils
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

# Additionally in windows 8.1 there are new fields StartingVpnHigh and
# EndingVpnHigh which are chars representing the high part of the PFN. Therefore
# the real PFN is (StartingVpnHigh << 32) | StartingVpn. The below overlay
# gracefully falls back to the old profiles (where StartingVpnHigh does not
# exist).
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
        'Start': lambda x: (
            x.StartingVpn + ((x.m("StartingVpnHigh") or 0) << 32)) << 12,

        'End': lambda x: (
            (x.EndingVpn + ((x.m("EndingVpnHigh") or 0) << 32))<<12)+0xFFF,

        'Length': lambda x: x.End - x.Start + 1,
        'CommitCharge': lambda x: x.u1.VadFlags1.CommitCharge,
        'LeftChild': lambda x: x.VadNode.Left,
        'RightChild': lambda x: x.VadNode.Right,
        }],

    '_MMVAD': [None, {
        'Tag': [TagOffset, ['String', dict(length=4)]],
        'ControlArea': lambda x: x.Subsection.ControlArea,

        # The following members proxy the embedded _MMVAD_SHORT in .Core.
        'Start': lambda x: x.Core.Start,
        'End': lambda x: x.Core.End,
        'Length': lambda x: x.Core.Length,
        'CommitCharge': lambda x: x.Core.CommitCharge,
        'u': lambda x: x.Core.u,
        'LeftChild': lambda x: x.Core.LeftChild,
        'RightChild': lambda x: x.Core.RightChild,
        }],

    '_MMVAD_LONG': [None, {
        'Tag': [TagOffset, ['String', dict(length=4)]],
        'ControlArea': lambda x: x.Subsection.ControlArea,

        # The following members proxy the embedded _MMVAD_SHORT in .Core.
        'Start': lambda x: x.Core.Start,
        'End': lambda x: x.Core.End,
        'Length': lambda x: x.Core.Length,
        'CommitCharge': lambda x: x.Core.CommitCharge,
        'u': lambda x: x.Core.u,
        'LeftChild': lambda x: x.Core.LeftChild,
        'RightChild': lambda x: x.Core.RightChild,
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
        "InfoMask": [None, ["Flags", dict(
            maskmap=utils.Invert({
                0x1: "CreatorInfo",
                0x2: "NameInfo",
                0x4: "HandleInfo",
                0x8: "QuotaInfo",
                0x10: "ProcessInfo",
                0x20: "AuditInfo",
                0x40: "PaddingInfo",
                }),
            target="unsigned char",
            )]],

        'GrantedAccess': lambda x: x.obj_parent.GrantedAccessBits
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

win8_1_overlays = {
    '_EPROCESS': [None, {
        # A symbolic link to the real vad root.
        'RealVadRoot': lambda x: x.VadRoot.Root
    }],

    '_HANDLE_TABLE': [None, {
        'HandleCount': lambda x: obj.NoneObject("Unknown")
    }],
}

win8_undocumented_amd64 = {
    # win8.1.raw 18:05:45> dis "nt!MiSessionInsertImage"
    # 0xf802d314344a   4E e871030300           CALL 0xf802d31737c0   nt!memset
    # ...
    # 0xf802d314345a   5E 48897b20             MOV [RBX+0x20], RDI
    '_IMAGE_ENTRY_IN_SESSION': [None, {
        'Link': [0, ['_LIST_ENTRY']],
        'Address': [0x20, ["Pointer"]],
    }],
}

win8_undocumented_i386 = {
    '_IMAGE_ENTRY_IN_SESSION': [None, {
        'Link': [0, ['_LIST_ENTRY']],
        'Address': [0x10, ["Pointer"]],
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
            target="byte", vm=cached_vm, count=0x100)]


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

    if profile.metadata("arch") == "AMD64":
        profile.add_overlay(win8_undocumented_amd64)
    else:
        profile.add_overlay(win8_undocumented_i386)

    # Win8.1 changed the vad data structures.
    if profile.metadata("version") >= 6.3:
        profile.add_overlay(win8_1_overlays)

    profile.add_classes(dict(
        _OBJECT_HEADER=win7._OBJECT_HEADER,
        _PSP_CID_TABLE=_PSP_CID_TABLE,
        _MM_AVL_NODE=_MM_AVL_NODE,
        _RTL_BALANCED_NODE=_RTL_BALANCED_NODE,
        _POOL_HEADER=win7._POOL_HEADER,
        ))

    # Windows 8 changes many of the pool tags. These come from windbg's
    # pooltag.txt.
    profile.add_constants(dict(
        DRIVER_POOLTAG="Driv",
        EPROCESS_POOLTAG="Proc",
        FILE_POOLTAG="File",
        SYMLINK_POOLTAG="Symb",
        MODULE_POOLTAG="MmLd",
        MUTANT_POOLTAG="Muta",
        THREAD_POOLTAG='Thre',
        ))
