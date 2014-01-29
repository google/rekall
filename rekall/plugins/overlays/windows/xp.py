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
    }


class _MMVAD(common.VadTraverser):
    """Windows XP uses the _MMVAD struct itself as a traversor.

    i.e. The _MMVAD contains the LeftChild and RightChild.
    """


def InitializeXPProfile(profile):
    profile.add_constants(PoolAlignment=8)
    profile.add_overlay(win_xp_overlays)
    profile.add_classes(dict(_MMVAD=_MMVAD))
