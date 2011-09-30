# Volatility
# Copyright (c) 2011 Michael Cohen <scudette@gmail.com>
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
Support for 64 bit Linux systems.

@author:      Michael Cohen
@license:      GNU General Public License 2.0 or later
@contact:      scudette@gmail.com
"""

import linux32
from volatility.plugins.overlays import basic
from volatility import obj

class VolatilityDTB(obj.VolatilityMagic):
    """A scanner for DTB values."""

    def generate_suggestions(self):
        """Tries to locate the DTB."""
        volmag = obj.Object('VOLATILITY_MAGIC', offset = 0, vm = self.obj_vm)

        # This is the difference between the virtual and physical addresses (aka
        # PAGE_OFFSET). On linux there is a direct mapping between physical and
        # virtual addressing in kernel mode:

        #define __va(x) ((void *)((unsigned long) (x) + PAGE_OFFSET))

        # We can also use the startup_64 but that seems to be defined twice (as
        # a Text symbol and a read only symbol).
        PAGE_OFFSET = volmag.SystemMap["_text"] - volmag.SystemMap["phys_startup_64"]

        yield volmag.SystemMap["init_level4_pgt"] - PAGE_OFFSET



class Linux64(linux32.Linux32):
    """Support for 64 bit linux systems."""
    _md_os = "linux"
    _md_memory_model = "64bit"

    native_types = basic.x86_native_types_64bit
    object_classes = linux32.Linux32.object_classes.copy()
    object_classes.update(
        dict(VolatilityDTB = VolatilityDTB))
