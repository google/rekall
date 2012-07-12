# Volatility
# Copyright (c) 2008-2011 Volatile Systems

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

import windows

from volatility import obj
from volatility.plugins.overlays import basic
from volatility.plugins.overlays.windows import windows


# In windows 7 the VadRoot is actually composed from _MMADDRESS_NODEs instead of
# _MMVAD structs.
win8_overlays = {
    '_EPROCESS': [ None, {
            'VadRoot': [ None, ['_MMADDRESS_NODE']]
            }],
    '_MMADDRESS_NODE': [ None, {
            'Tag': [-12, ['String', dict(length=4)]],
            }],

    '_MMVAD_SHORT': [ None, {
            'Tag': [-12 , ['String', dict(length = 4)]],
            }],

    '_MMVAD': [ None, {
            'Tag': [-12 , ['String', dict(length = 4)]],
            'ControlArea': lambda x: x.Subsection.ControlArea,
            }],

    '_MMVAD_LONG': [ None, {
            'Tag': [-12 , ['String', dict(length = 4)]],
            'ControlArea': lambda x: x.Subsection.ControlArea,
            }],

    "_CONTROL_AREA": [None, {
            'FilePointer': [None, ['_EX_FAST_REF', dict(target="_FILE_OBJECT")]],
            }],
    }


class _OBJECT_HEADER(windows._OBJECT_HEADER):
    """A Volatility object to handle Windows 7 object headers.

    Windows 7 changes the way objects are handled:
    References: http://www.codemachine.com/article_objectheader.html
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
            else:
                o = obj.NoneObject("Header not set")

            self.newattr(name, o)

    def get_object_type(self, kernel_address_space):
        """Return the object's type as a string"""
        return self.type_map.get(self.TypeIndex.v(), '')


class _MMADDRESS_NODE(windows._MMVAD):
    """In win7 the base class of all Vad objects in _MMADDRESS_NODE."""
    @property
    def Parent(self):
        return self.u1.Parent


class _MMVAD_SHORT(_MMADDRESS_NODE):
    pass


class _HANDLE_TABLE(obj.CType):
    @property
    def HandleCount(self):
        # We dont know how to figure this out yet!
        return 0


class Win8BaseProfile(windows.BaseWindowsProfile):
    """The common ancestor of all windows 7 profiles."""

    __abstract = True

    def __init__(self, **kwargs):
        super(Win8BaseProfile, self).__init__(**kwargs)
        self.add_types({
                'pointer64': ['NativeType', dict(format_string='<Q')]
                })
        self.add_overlay(win8_overlays)

        self.add_classes(dict(_OBJECT_HEADER=_OBJECT_HEADER,
                              _MMADDRESS_NODE=_MMADDRESS_NODE,
                              _MMVAD_SHORT=_MMVAD_SHORT,
                              _HANDLE_TABLE=_HANDLE_TABLE,
                              pointer64=obj.Pointer))


class Win8SP0x86(basic.Profile32Bits, Win8BaseProfile):
    """ A Profile for Windows 8 SP0 x86 """
    _md_major = 6
    _md_minor = 2

    def __init__(self, **kwargs):
        super(Win8SP0x86, self).__init__(**kwargs)

        # Import the actual vtypes on demand here to reduce memory usage.
        from volatility.plugins.overlays.windows import win8_sp0_x86_vtypes

        self.add_types(win8_sp0_x86_vtypes.ntkrnlmp_types)


class Win8SP0x64(basic.Profile64Bits, Win8BaseProfile):
    """ A Profile for Windows 8 SP0 x64 """
    _md_major = 6
    _md_minor = 2

    def __init__(self, **kwargs):
        super(Win8SP0x64, self).__init__(**kwargs)

        # Import the actual vtypes on demand here to reduce memory usage.
        from volatility.plugins.overlays.windows import win8_sp0_x64_vtypes

        self.add_types(win8_sp0_x64_vtypes.ntkrnlmp_types)
