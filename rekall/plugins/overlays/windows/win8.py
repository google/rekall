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

from rekall import obj
from rekall.plugins.overlays.windows import win7


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
            'Tag': [-12, ['String', dict(length=4)]],
            }],

    '_MMVAD_SHORT': [None, {
            'Tag': [-12, ['String', dict(length=4)]],
            'Start': lambda x: x.StartingVpn << 12,
            'End': lambda x: ((x.EndingVpn + 1) << 12) - 1,
            'CommitCharge': lambda x: x.u1.VadFlags1.CommitCharge,
            }],

    '_MMVAD': [None, {
            'Tag': [-12, ['String', dict(length=4)]],
            'ControlArea': lambda x: x.Subsection.ControlArea,
            'Start': lambda x: x.Core.StartingVpn << 12,
            'End': lambda x: ((x.Core.EndingVpn + 1) << 12) - 1,
            'CommitCharge': lambda x: x.Core.u1.VadFlags1.CommitCharge,
            'u': lambda x: x.Core.u,
            }],

    "_CONTROL_AREA": [None, {
            'FilePointer': [None, ['_EX_FAST_REF', dict(
                        target="_FILE_OBJECT"
                        )]],
            }],
    }


class _OBJECT_HEADER(win7._OBJECT_HEADER):
    """A Rekall Memory Forensics object to handle Windows 7 object headers.

    Windows 7 changes the way objects are handled:
    References: http://www.codemachine.com/article_objectheader.html
    """

    type_map = {2: 'Type',
                3: 'Directory',
                4: 'SymbolicLink',
                5: 'Token',
                6: 'Job',
                7: 'Process',
                8: 'Thread',
                9: 'UserApcReserve',
                10: 'IoCompletionReserve',
                11: 'DebugObject',
                12: 'Event',
                13: 'EventPair',
                14: 'Mutant',
                15: 'Callback',
                16: 'Semaphore',
                17: 'Timer',
                18: 'Profile',
                19: 'KeyedEvent',
                20: 'WindowStation',
                21: 'Desktop',
                22: 'TpWorkerFactory',
                23: 'Adapter',
                24: 'Controller',
                25: 'Device',
                26: 'Driver',
                27: 'IoCompletion',
                28: 'File',
                29: 'TmTm',
                30: 'TmTx',
                31: 'TmRm',
                32: 'TmEn',
                33: 'Section',
                34: 'Session',
                35: 'Key',
                36: 'ALPC Port',
                37: 'PowerRequest',
                38: 'WmiGuid',
                39: 'EtwRegistration',
                40: 'EtwConsumer',
                41: 'FilterConnectionPort',
                42: 'FilterCommunicationPort',
                43: 'PcwObject',
                }

    # This specifies the order the headers are found below the _OBJECT_HEADER
    optional_header_mask = (
        ('CreatorInfo', '_OBJECT_HEADER_CREATOR_INFO', 0x01),
        ('NameInfo', '_OBJECT_HEADER_NAME_INFO', 0x02),
        ('HandleInfo', '_OBJECT_HEADER_HANDLE_INFO', 0x04),
        ('QuotaInfo', '_OBJECT_HEADER_QUOTA_INFO', 0x08),
        ('ProcessInfo', '_OBJECT_HEADER_PROCESS_INFO', 0x10),
        ('AuditInfo', '_OBJECT_HEADER_AUDIT_INFO', 0x40),
        )

    def find_optional_headers(self):
        """Find this object's optional headers."""
        offset = self.obj_offset

        info_mask = int(self.InfoMask)

        for name, struct, mask in self.optional_header_mask:
            if info_mask & mask:
                offset -= self.obj_profile.get_obj_size(struct)
                o = self.obj_profile.Object(type_name=struct, offset=offset,
                                            vm=self.obj_vm)
                self._preamble_size += o.size()
            else:
                o = obj.NoneObject("Header not set")

            setattr(self, name, o)

    def get_object_type(self, kernel_address_space):
        """Return the object's type as a string"""
        return self.type_map.get(self.TypeIndex.v(), '')

    def is_valid(self):
        """Determine if the object makes sense."""
        # These need to be reasonable.
        pointer_count = int(self.PointerCount)
        if pointer_count > 0x100000 or pointer_count < 0:
            return False

        handle_count = int(self.HandleCount)
        if handle_count > 0x1000 or handle_count < 0:
            return False

        if  (self.TypeIndex >= len(self.type_map) or
             self.TypeIndex < 1):
            return False

        return True


class _HANDLE_TABLE(obj.Struct):
    @property
    def HandleCount(self):
        # We dont know how to figure this out yet!
        return 0



class _POOL_HEADER(obj.Struct):
    MAX_PREAMBLE_SIZE = 0xa0

    @property
    def NonPagedPool(self):
        return self.PoolType.v() % 2 == 0 and self.PoolType.v() > 0

    @property
    def PagedPool(self):
        return self.PoolType.v() % 2 == 1

    @property
    def FreePool(self):
        return self.PoolType.v() == 0

    def get_next_object(self, offset, object_name):
        """Gets the next object that fits after this offset."""
        pool_align = self.obj_profile.get_constant("PoolAlignment")
        for preamble in range(0, self.MAX_PREAMBLE_SIZE, pool_align):
            result = self.obj_profile.Object(object_name, vm=self.obj_vm,
                                             offset=offset + preamble)

            # If the object preamble is exactly what we expect, we found it.
            if result.preamble_size() == preamble:
                try:
                    # Allow the object to check for its own validity.
                    if result.is_valid():
                        return result
                except AttributeError:
                    return result

    def get_object(self, object_name, allocations):
        """On windows 8, pool allocations are done from preset sizes. This means
        that the allocation is never exactly the same size and we can not use
        the bottom up method like before.

        We therefore, have to build the headers forward by checking the preamble
        size and validity of each object. This is a little slower than with
        earlier versions of windows.
        """
        objects = []

        offset = self.obj_offset

        for name in allocations:
            result = self.get_next_object(offset, name)
            if not result:
                return obj.NoneObject("Object not found.")

            offset = result.obj_offset + result.size()
            objects.append(result)

            # Return to the caller.
            if name == object_name:
                return result

        raise KeyError("object not present in preamble.")


class _MM_AVL_NODE(win7._MMADDRESS_NODE):
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


def InitializeWindows8Profile(profile):
    profile.add_overlay(win8_overlays)

    profile.add_classes(dict(_OBJECT_HEADER=_OBJECT_HEADER,
                             _HANDLE_TABLE=_HANDLE_TABLE,
                             _MM_AVL_NODE=_MM_AVL_NODE,
                             pointer64=obj.Pointer))

    # Windows 8 changes many of the pool tags.
    profile.add_constants(
        EPROCESS_POOLTAG="Proc",
        DRIVER_POOLTAG="Driv",
        )

    profile.add_classes(dict(_POOL_HEADER=_POOL_HEADER))
