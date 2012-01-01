# Volatility
# Copyright (c) 2008 Volatile Systems
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
@author:       Michael Cohen
@license:      GNU General Public License 2.0 or later
@contact:      scudette@gmail.com

This file provides support for Windows 7 SP 1 64 bit version. Many thanks to
Alex Pease (alex.pease@gmail.com) for his assistance.
"""

#pylint: disable-msg=C0111

import copy
import win7_sp1_x86
import win7_sp1_x64_vtypes
import win7_sp0_x86_syscalls
import windows
import tcpip_vtypes
import crash_vtypes
import hibernate_vtypes
import kdbg_vtypes
import volatility.debug as debug #pylint: disable-msg=W0611

win7sp1x64overlays_update = {
    '_KTHREAD': [None, {
        'ServiceTable': lambda x: x.Spare0,
        }],

    # This is the location of the MMVAD type which controls how to parse the
    # node. It is located before the structure.
    '_MMVAD_LONG': [None, {
        'Tag': [-12, ['String', dict(length = 4)]],
        }],
    '_MMVAD_SHORT': [None, {
        'Tag': [-12, ['String', dict(length = 4)]],
        }],

    'VOLATILITY_MAGIC': [None, {
        'DTBSignature': [None, ['VolatilityMagic', dict(value = "\x03\x00\x58\x00")]],
        'KPCR': [None, ['VolatilityKPCR', dict(value = 0xffdff000, configname = 'KPCR')]],
        'KDBGHeader': [None, ['VolatilityMagic', dict(value = '\x00\xf8\xff\xffKDBG\x40\x03')]],
        'HiveListOffset': [None, ['VolatilityMagic', dict(value = 0x5d8)]],
        'HiveListPoolSize': [None, ['VolatilityMagic', dict(value = 0xBF6)]],
        'PoolAlignment': [0x0, ['VolatilityMagic', dict(value = 16)]],
        'TypeIndexMap': [0x0, ['VolatilityMagic', dict(value = {
            2: 'Type',
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
            })]],
            }],
    }

win7_sp1_x64_vtypes.ntkrnlmp_types.update(crash_vtypes.crash_vtypes)
win7_sp1_x64_vtypes.ntkrnlmp_types.update(hibernate_vtypes.hibernate_vtypes)
win7_sp1_x64_vtypes.ntkrnlmp_types.update(kdbg_vtypes.kdbg_vtypes)
win7_sp1_x64_vtypes.ntkrnlmp_types.update(tcpip_vtypes.tcpip_vtypes)
win7_sp1_x64_vtypes.ntkrnlmp_types.update(tcpip_vtypes.tcpip_vtypes_vista)
win7_sp1_x64_vtypes.ntkrnlmp_types.update(tcpip_vtypes.tcpip_vtypes_7)

# On win7 this struct is named differently.
win7_sp1_x64_vtypes.ntkrnlmp_types["_IMAGE_NT_HEADERS"] = win7_sp1_x64_vtypes.ntkrnlmp_types["_IMAGE_NT_HEADERS64"]

new_overlay = windows.AbstractWindowsx64.apply_overlay(
    win7_sp1_x86.win7sp1x86overlays, win7sp1x64overlays_update)

# The following overlays should be removed. They are handled well in our vtypes
new_overlay.pop("_POOL_HEADER", None)


class Win7SP1x64(windows.AbstractWindowsx64):
    """ A Profile for Windows 7 SP1 x64 """
    _md_major = 7
    _md_minor = 1
    abstract_types = win7_sp1_x64_vtypes.ntkrnlmp_types
    overlay = new_overlay
    object_classes = copy.deepcopy(win7_sp1_x86.Win7SP1x86.object_classes)
    syscalls = win7_sp0_x86_syscalls.syscalls
