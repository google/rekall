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
from rekall import kb
from rekall import obj
from rekall.plugins.overlays.windows import common


# In windows 7 the VadRoot is actually composed from _MMADDRESS_NODEs instead of
# _MMVAD structs.
win7_overlays = {
    '_EPROCESS': [None, {
            # A symbolic link to the real vad root.
            'RealVadRoot': lambda x: x.VadRoot.BalancedRoot
            }],

    '_MMADDRESS_NODE': [None, {
            'Tag': [-12, ['String', dict(length=4)]],
            }],

    '_MMVAD_SHORT': [None, {
            'Tag': [-12, ['String', dict(length=4)]],
            'Start': lambda x: x.StartingVpn << 12,
            'End': lambda x: ((x.EndingVpn + 1) << 12) - 1,
            'Length': lambda x: x.End - x.Start + 1,
            'CommitCharge': lambda x: x.u.VadFlags.CommitCharge,
            }],

    '_MMVAD': [None, {
            'Tag': [-12, ['String', dict(length=4)]],
            'ControlArea': lambda x: x.Subsection.ControlArea,
            'Start': lambda x: x.StartingVpn << 12,
            'End': lambda x: ((x.EndingVpn + 1) << 12) - 1,
            'Length': lambda x: x.End - x.Start + 1,
            'CommitCharge': lambda x: x.u.VadFlags.CommitCharge,
            }],

    '_MMVAD_LONG': [None, {
            'Tag': [-12, ['String', dict(length=4)]],
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
    }


class _OBJECT_HEADER(common._OBJECT_HEADER):
    """A Rekall Memory Forensics object to handle Windows 7 object headers.

    Windows 7 changes the way objects are handled:
    References: http://www.codemachine.com/article_objectheader.html
    """

    # This specifies the order the headers are found below the _OBJECT_HEADER
    optional_header_mask = (
        ('CreatorInfo', '_OBJECT_HEADER_CREATOR_INFO', 0x01),
        ('NameInfo', '_OBJECT_HEADER_NAME_INFO', 0x02),
        ('HandleInfo', '_OBJECT_HEADER_HANDLE_INFO', 0x04),
        ('QuotaInfo', '_OBJECT_HEADER_QUOTA_INFO', 0x08),
        ('ProcessInfo', '_OBJECT_HEADER_PROCESS_INFO', 0x10))

    def find_optional_headers(self):
        """Find this object's optional headers."""
        offset = self.obj_offset
        info_mask = int(self.InfoMask)

        for name, struct, mask in self.optional_header_mask:
            if info_mask & mask:
                offset -= self.obj_profile.get_obj_size(struct)
                o = self.obj_profile.Object(
                    type_name=struct, offset=offset, vm=self.obj_vm)
                self._preamble_size += o.size()
            else:
                o = obj.NoneObject("Header not set")

            setattr(self, name, o)

    def get_object_type(self, vm=None):
        """Return the object's type as a string"""
        return self.obj_session.GetParameter("ObjectTypeMap")[
            self.TypeIndex].Name.v()

    def is_valid(self):
        """Determine if the object makes sense."""
        # These need to be reasonable.
        if (self.PointerCount < 0x100000 and self.HandleCount < 0x1000 and
            self.PointerCount >= 0 and self.HandleCount >= 0 and
            self.TypeIndex <= len(self.type_map) and
            self.TypeIndex > 0):
            return True

        return False


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

    @property
    def NonPagedPool(self):
        return self.PoolType.v() % 2 == 0 and self.PoolType.v() > 0

    @property
    def PagedPool(self):
        return self.PoolType.v() % 2 == 1


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
