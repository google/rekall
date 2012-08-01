# Volatility
# Copyright (c) 2008-2011 Volatile Systems
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

#pylint: disable-msg=C0111

import windows
from volatility import obj
from volatility.plugins.overlays import basic
from volatility.plugins.overlays.windows import windows


# In windows 7 the VadRoot is actually composed from _MMADDRESS_NODEs instead of
# _MMVAD structs.
win7_overlays = {
    '_EPROCESS': [ None, {
            # A symbolic link to the real vad root.
            'RealVadRoot': lambda x: x.VadRoot.BalancedRoot
            }],

    '_MMADDRESS_NODE': [ None, {
            'Tag': [-12, ['String', dict(length=4)]],
            }],

    '_MMVAD_SHORT': [ None, {
            'Tag': [-12 , ['String', dict(length = 4)]],
            'Start': lambda x: x.StartingVpn << 12,
            'End': lambda x: ((x.EndingVpn + 1) << 12) - 1,
            'Length': lambda x: x.End - x.Start + 1,
            'CommitCharge': lambda x: x.u.VadFlags.CommitCharge,
            }],

    '_MMVAD': [ None, {
            'Tag': [-12 , ['String', dict(length = 4)]],
            'ControlArea': lambda x: x.Subsection.ControlArea,
            'Start': lambda x: x.StartingVpn << 12,
            'End': lambda x: ((x.EndingVpn + 1) << 12) - 1,
            'Length': lambda x: x.End - x.Start + 1,
            'CommitCharge': lambda x: x.u.VadFlags.CommitCharge,
            }],

    '_MMVAD_LONG': [ None, {
            'Tag': [-12 , ['String', dict(length = 4)]],
            'ControlArea': lambda x: x.Subsection.ControlArea,
            'Start': lambda x: x.StartingVpn << 12,
            'End': lambda x: ((x.EndingVpn + 1) << 12) - 1,
            'Length': lambda x: x.End - x.Start + 1,
            'CommitCharge': lambda x: x.u.VadFlags.CommitCharge,
            }],

    "_CONTROL_AREA": [None, {
            'FilePointer': [None, ['_EX_FAST_REF', dict(target="_FILE_OBJECT")]],
            }],
    }


class _OBJECT_HEADER(windows._OBJECT_HEADER):
    """A Volatility object to handle Windows 7 object headers.

    Windows 7 changes the way objects are handled:
    References: http://www.codemachine.com/article_objectheader.html

    The following debugger command find the type object for index 5:
    dt nt!_OBJECT_TYPE poi(nt!ObTypeIndexTable + ( 5 * @$ptrsize ))
    """
    type_map = { 2: 'Type',
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
    optional_header_mask = (('CreatorInfo', '_OBJECT_HEADER_CREATOR_INFO', 0x01),
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
                o = self.obj_profile.Object(theType=struct, offset=offset, vm=self.obj_vm)
                self._preamble_size += o.size()
            else:
                o = obj.NoneObject("Header not set")

            self.newattr(name, o)

    def get_object_type(self, kernel_address_space):
        """Return the object's type as a string"""
        return self.type_map.get(self.TypeIndex.v(), '')

    def is_valid(self):
        """Determine if the object makes sense."""
        # These need to be reasonable.
        if (self.PointerCount < 0x100000 and self.HandleCount < 0x1000 and
            self.PointerCount >= 0 and self.HandleCount >= 0 and
            self.TypeIndex <= len(self.type_map) and
            self.TypeIndex > 0):
            return True

        return False


class _MMADDRESS_NODE(windows.VadTraverser):
    """In win7 the base of all Vad objects in _MMADDRESS_NODE.

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


class Win7BaseProfile(windows.BaseWindowsProfile):
    """The common ancestor of all windows 7 profiles."""

    __abstract = True

    def __init__(self, **kwargs):
        super(Win7BaseProfile, self).__init__(**kwargs)
        self.add_types({
                'pointer64': ['NativeType', dict(format_string='<Q')]
                })
        self.add_overlay(win7_overlays)

        self.add_classes(dict(_OBJECT_HEADER=_OBJECT_HEADER,
                              _MMADDRESS_NODE=_MMADDRESS_NODE,
                              pointer64=obj.Pointer))


class Win7SP0x86(basic.Profile32Bits, Win7BaseProfile):
    """ A Profile for Windows 7 SP0 x86 """
    _md_major = 6
    _md_minor = 1
    _md_type = "Kernel"

    def __init__(self, **kwargs):
        super(Win7SP0x86, self).__init__(**kwargs)

        # Import the actual vtypes on demand here to reduce memory usage.
        from volatility.plugins.overlays.windows import win7_sp0_x86_vtypes

        self.add_types(win7_sp0_x86_vtypes.ntkrnlmp_types)


class Win7SP0x64(basic.Profile64Bits, Win7BaseProfile):
    """ A Profile for Windows 7 SP0 x64 """
    _md_major = 6
    _md_minor = 1
    _md_type = "Kernel"

    def __init__(self, **kwargs):
        super(Win7SP0x64, self).__init__(**kwargs)

        # Import the actual vtypes on demand here to reduce memory usage.
        from volatility.plugins.overlays.windows import win7_sp0_x64_vtypes

        self.add_types(win7_sp0_x64_vtypes.ntkrnlmp_types)


class Win7SP1x86(basic.Profile32Bits, Win7BaseProfile):
    """ A Profile for Windows 7 SP1 x86 """
    _md_major = 6
    _md_minor = 1
    _md_build = 7601
    _md_type = "Kernel"

    def __init__(self, **kwargs):
        super(Win7SP1x86, self).__init__(**kwargs)
        self.add_constants(kdbgsize=0x340)

        # Import the actual vtypes on demand here to reduce memory usage.
        from volatility.plugins.overlays.windows import win7_sp1_x86_vtypes

        self.add_types(win7_sp1_x86_vtypes.ntkrnlmp_types)


class Win7SP1x64(basic.Profile64Bits, Win7BaseProfile):
    """ A Profile for Windows 7 SP1 x64 """
    _md_major = 6
    _md_minor = 1
    _md_type = "Kernel"

    def __init__(self, **kwargs):
        super(Win7SP1x64, self).__init__(**kwargs)
        self.add_constants(kdbgsize=0x340)

        # Import the actual vtypes on demand here to reduce memory usage.
        from volatility.plugins.overlays.windows import win7_sp1_x64_vtypes

        self.add_types(win7_sp1_x64_vtypes.ntkrnlmp_types)

class Win2008R2SP0x64(Win7SP0x64):
    """ A Profile for Windows 2008 R2 SP0 x64 """


class Win2008R2SP1x64(Win7SP1x64):
    """ A Profile for Windows 2008 R2 SP1 x64 """
