# Rekall Memory Forensics
# Copyright (c) 2008 Volatile Systems
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
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

This file provides support for windows Vista.
"""

# pylint: disable=protected-access

from rekall.plugins.overlays.windows import common


vista_overlays = {
    '_EPROCESS': [None, {
        # A symbolic link to the real vad root.
        'RealVadRoot': lambda x: x.VadRoot.BalancedRoot
    }],

    '_MMADDRESS_NODE': [None, {
        'Tag': [-4, ['String', dict(length=4)]],
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
        'ControlArea': lambda x: x.Subsection.ControlArea,
        'Start': lambda x: x.StartingVpn << 12,
        'End': lambda x: ((x.EndingVpn + 1) << 12) - 1,
        'Length': lambda x: x.End - x.Start + 1,
        'CommitCharge': lambda x: x.u.VadFlags.CommitCharge,
    }],

    '_MMVAD_LONG': [None, {
        'Tag': [-4, ['String', dict(length=4)]],
        'ControlArea': lambda x: x.Subsection.ControlArea,
        'Start': lambda x: x.StartingVpn << 12,
        'End': lambda x: ((x.EndingVpn + 1) << 12) - 1,
        'Length': lambda x: x.End - x.Start + 1,
        'CommitCharge': lambda x: x.u.VadFlags.CommitCharge,
    }],

    "_CONTROL_AREA": [None, {
        'FilePointer': [None, ['_EX_FAST_REF', dict(
            target="_FILE_OBJECT")]],
    }],
    '_MM_SESSION_SPACE': [None, {
        # Specialized iterator to produce all the _IMAGE_ENTRY_IN_SESSION
        # records.
        'ImageIterator': lambda x: x.ImageList.list_of_type(
            "_IMAGE_ENTRY_IN_SESSION", "Link")
    }],

    '_IMAGE_ENTRY_IN_SESSION': [None, {
        'ImageBase': lambda x: x.Address.v() & ~7
    }]
}


class _MMADDRESS_NODE(common.VadTraverser):
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


class _ETHREAD(common._ETHREAD):
    """A class for Windows 7 ETHREAD objects"""

    def owning_process(self):
        """Return the EPROCESS that owns this thread"""
        return self.Tcb.Process.dereference_as("_EPROCESS")


def InitializeVistaProfile(profile):
    if profile.metadata("arch") == "AMD64":
        profile.add_constants(dict(PoolAlignment=16))
    else:
        profile.add_constants(dict(PoolAlignment=8))
    profile.add_overlay(vista_overlays)
    profile.add_classes(dict(
        _ETHREAD=_ETHREAD,
        _MMADDRESS_NODE=_MMADDRESS_NODE
    ))
