# Rekall Memory Forensics
# Copyright (c) 2008 Volatile Systems
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
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
@author:       Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      bdolangavitt@wesleyan.edu

This file provides support for windows XP SP2. We provide a profile
for SP2.
"""

from rekall.plugins.overlays.windows import common


# Windows XP specific overlays.
win_xp_overlays = {
    '_EPROCESS' : [None, {
        'VadRoot': [None, ['pointer', ['_MMVAD']]],
        'RealVadRoot': lambda x: x.VadRoot.dereference(),
    }],

    '_MMVAD_SHORT': [None, {
        'Tag': [-4, ['String', dict(length=4)]],
        'Start': lambda x: x.StartingVpn << 12,
        'End': lambda x: ((x.EndingVpn + 1) << 12) - 1,
        'Length': lambda x: x.End - x.Start + 1,
        'CommitCharge': lambda x: x.u.VadFlags.CommitCharge,
    }],

    '_MMVAD': [None, {
        'Tag': [-4, ['String', dict(length=4)]],
        'Start': lambda x: x.StartingVpn << 12,
        'End': lambda x: ((x.EndingVpn + 1) << 12) - 1,
        'Length': lambda x: x.End - x.Start + 1,
        'CommitCharge': lambda x: x.u.VadFlags.CommitCharge,
    }],

    '_MMVAD_LONG': [None, {
        'Tag': [-4, ['String', dict(length=4)]],
        'Start': lambda x: x.StartingVpn << 12,
        'End': lambda x: ((x.EndingVpn + 1) << 12) - 1,
        'Length': lambda x: x.End - x.Start + 1,
        'CommitCharge': lambda x: x.u.VadFlags.CommitCharge,
    }],

    # This is not documented in Windows XP but is in Windows 7.
    "_OBJECT_HEADER_HANDLE_INFO": [16, {
        "HandleCountDataBase": [0, ["Pointer", {
            "target": "_OBJECT_HANDLE_COUNT_DATABASE"
            }]],
        "SingleEntry": [0, ["_OBJECT_HANDLE_COUNT_ENTRY", {}]]
    }],

    "_OBJECT_HANDLE_COUNT_ENTRY": [16, {
        "HandleCount": [8, ["BitField", {
            "end_bit": 24,
            "target": "unsigned long"
            }]],
        "LockCount": [8, ["BitField", {
            "end_bit": 32,
            "start_bit": 24,
            "target": "unsigned long"
            }]],
        "Process": [0, ["Pointer", {
            "target": "_EPROCESS"
            }]]
        }],

    '_MM_SESSION_SPACE': [None, {
        # Specialized iterator to produce all the _IMAGE_ENTRY_IN_SESSION
        # records.
        'ImageIterator': lambda x: x.ImageList.list_of_type(
            "_IMAGE_ENTRY_IN_SESSION", "Link")
    }],

    '_IMAGE_ENTRY_IN_SESSION': [None, {
        'ImageBase': lambda x: x.Address.v()
    }],
}


class _MMVAD(common.VadTraverser):
    """Windows XP uses the _MMVAD struct itself as a traversor.

    i.e. The _MMVAD contains the LeftChild and RightChild.
    """


def InitializeXPProfile(profile):
    if profile.metadata("arch") == "AMD64":
        profile.add_constants(dict(PoolAlignment=16))
    else:
        profile.add_constants(dict(PoolAlignment=8))
    profile.add_overlay(win_xp_overlays)
    profile.add_classes(dict(_MMVAD=_MMVAD))
