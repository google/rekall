# Volatility
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

This file provides support for windows XP SP3. We provide a profile
for SP3.
"""

from volatility import obj
from volatility.plugins.overlays import basic
from volatility.plugins.overlays.windows import windows
from volatility.plugins.overlays.windows import xp


# In windows 7 the VadRoot is actually composed from _MMADDRESS_NODEs instead of
# _MMVAD structs.
vista_overlays = {
    '_EPROCESS': [ None, {
            # A symbolic link to the real vad root.
            'RealVadRoot': lambda x: x.VadRoot.BalancedRoot
            }],

    '_MMADDRESS_NODE': [ None, {
            'Tag': [-4, ['String', dict(length=4)]],
            }],

    '_MMVAD_SHORT': [ None, {
            'Tag': [-4 , ['String', dict(length = 4)]],
            'Start': lambda x: x.StartingVpn << 12,
            'End': lambda x: ((x.EndingVpn + 1) << 12) - 1,
            'Length': lambda x: x.End - x.Start + 1,
            'CommitCharge': lambda x: x.u.VadFlags.CommitCharge,
            }],

    '_MMVAD': [ None, {
            'Tag': [-4 , ['String', dict(length = 4)]],
            'ControlArea': lambda x: x.Subsection.ControlArea,
            'Start': lambda x: x.StartingVpn << 12,
            'End': lambda x: ((x.EndingVpn + 1) << 12) - 1,
            'Length': lambda x: x.End - x.Start + 1,
            'CommitCharge': lambda x: x.u.VadFlags.CommitCharge,
            }],

    '_MMVAD_LONG': [ None, {
            'Tag': [-4 , ['String', dict(length = 4)]],
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


class _ETHREAD(windows._ETHREAD):
    """A class for Windows 7 ETHREAD objects"""

    def owning_process(self):
        """Return the EPROCESS that owns this thread"""
        return self.Tcb.Process.dereference_as("_EPROCESS")

class VistaWin7KPCR(obj.ProfileModification):
    before = ['WindowsOverlay']
    conditions = {'os' : lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'memory_model': lambda x: x == '32bit'}

    def modification(self, profile):
        overlay = {'VOLATILITY_MAGIC': [ None, {
                    'KPCR' : [ None, ['VolatilityKPCR', dict(configname = "KPCR")]],
                                          }]}
        profile.merge_overlay(overlay)

class Vistax86DTB(obj.ProfileModification):
    before = ['WindowsOverlay']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 0,
                  'memory_model': lambda x: x == '32bit',
                  }

    def modification(self, profile):
        overlay = {'VOLATILITY_MAGIC': [ None, {
                    'DTBSignature' : [ None, ['VolatilityMagic', dict(value = "\x03\x00\x20\x00")]],
                                          }]}
        profile.merge_overlay(overlay)

class Vistax64DTB(obj.ProfileModification):
    before = ['WindowsOverlay', 'Windows64Overlay']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 0,
                  'memory_model': lambda x: x == '64bit',
                  }

    def modification(self, profile):
        overlay = {'VOLATILITY_MAGIC': [ None, {
                    'DTBSignature' : [ None, ['VolatilityMagic', dict(value = "\x03\x00\x30\x00")]],
                                          }]}
        profile.merge_overlay(overlay)


class AbstractVistaProfile(windows.BaseWindowsProfile):
    """Vista profile base."""
    _md_major = 6
    _md_minor = 0
    _md_os = 'windows'

    def __init__(self, **kwargs):
        super(AbstractVistaProfile, self).__init__(**kwargs)
        self.add_constants(PoolAlignment = 8)

        self.add_overlay(vista_overlays)

        self.add_classes(dict(
                _ETHREAD=_ETHREAD,
                _MMADDRESS_NODE=_MMADDRESS_NODE
                ))

class VistaSP0x86(obj.Profile):
    """ A Profile for Windows Vista SP0 x86 """
    _md_build = 6000
    _md_memory_model = '32bit'

    def __init__(self, **kwargs):
        super(VistaSP0x86, self).__init__(**kwargs)
        from volatility.plugins.overlays.windows import vista_sp0_x86_vtypes

        self.add_types(vista_sp0_x86_vtypes.ntkrnlmp_types)


class VistaSP0x64(obj.Profile):
    """ A Profile for Windows Vista SP0 x64 """
    _md_build = 6000
    _md_memory_model = '64bit'

    def __init__(self, **kwargs):
        super(VistaSP0x64, self).__init__(**kwargs)
        from volatility.plugins.overlays.windows import vista_sp0_x64_vtypes

        self.add_types(vista_sp0_x64_vtypes.ntkrnlmp_types)


class VistaSP1x86(basic.Profile32Bits, AbstractVistaProfile):
    """A Profile for Windows Vista SP1 x86."""
    _md_build = 6001
    _md_memory_model = '32bit'

    def __init__(self, **kwargs):
        super(VistaSP1x86, self).__init__(**kwargs)
        from volatility.plugins.overlays.windows import vista_sp1_x86_vtypes

        self.add_types(vista_sp1_x86_vtypes.ntkrnlmp_types)


class VistaSP1x64(basic.Profile64Bits, AbstractVistaProfile):
    """A Profile for Windows Vista SP1 x64."""
    _md_build = 6001
    _md_memory_model = '64bit'

    def __init__(self, **kwargs):
        super(VistaSP1x64, self).__init__(**kwargs)
        from volatility.plugins.overlays.windows import vista_sp1_x64_vtypes

        self.add_types(vista_sp1_x64_vtypes.ntkrnlmp_types)


class VistaSP2x86(basic.Profile32Bits, AbstractVistaProfile):
    """ A Profile for Windows Vista SP2 x86 """
    _md_build = 6002
    _md_memory_model = '32bit'

    def __init__(self, **kwargs):
        super(VistaSP1x86, self).__init__(**kwargs)
        from volatility.plugins.overlays.windows import vista_sp2_x86_vtypes

        self.add_types(vista_sp2_x86_vtypes.ntkrnlmp_types)

class VistaSP2x64(basic.Profile64Bits, AbstractVistaProfile):
    """ A Profile for Windows Vista SP2 x64 """
    _md_build = 6002
    _md_memory_model = '64bit'

    def __init__(self, **kwargs):
        super(VistaSP1x64, self).__init__(**kwargs)
        from volatility.plugins.overlays.windows import vista_sp2_x64_vtypes

        self.add_types(vista_sp2_x64_vtypes.ntkrnlmp_types)


class Win2008SP1x64(VistaSP1x64):
    """ A Profile for Windows 2008 SP1 x64 """

class Win2008SP2x64(VistaSP2x64):
    """ A Profile for Windows 2008 SP2 x64 """

class Win2008SP1x86(VistaSP1x86):
    """ A Profile for Windows 2008 SP1 x86 """

class Win2008SP2x86(VistaSP2x86):
    """ A Profile for Windows 2008 SP2 x86 """
