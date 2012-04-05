# Volatility
# Copyright (C) 2008 Volatile Systems
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
@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com,bdolangavitt@wesleyan.edu
@organization: Volatile Systems
"""

from volatility.plugins.windows import common


class PoolScanHive(common.PoolScanner):
    checks = [ ('PoolTagCheck', dict(tag = "CM10")) ]

    def scan(self):
        pool_header_size = self.profile.get_obj_size("_POOL_HEADER")
        for hit in super(PoolScanHive, self).scan():
            # The _HHIVE is immediately after the pool header.
            hhive = self.profile.Object("_CMHIVE", offset=hit + pool_header_size,
                                        vm=self.address_space)
            if hhive.Hive.Signature != 0xbee0bee0:
                continue

            yield hhive


class HiveScan(common.PoolScannerPlugin):
    """ Scan Physical memory for _CMHIVE objects (registry hives)

    You will need to obtain these offsets to feed into the hivelist command.
    """

    __name = "hivescan"

    meta_info = dict(
        author = 'Brendan Dolan-Gavitt',
        copyright = 'Copyright (c) 2007,2008 Brendan Dolan-Gavitt',
        contact = 'bdolangavitt@wesleyan.edu',
        license = 'GNU General Public License 2.0 or later',
        url = 'http://moyix.blogspot.com/',
        os = 'WIN_32_XP_SP2',
        version = '1.0',
        )

    def generate_hits(self, address_space=None):
        """Yields potential _HHIVE objects."""
        # Scan for these in the kernel address space.
        address_space = address_space or self.physical_address_space
        scanner = PoolScanHive(profile=self.profile, address_space=address_space)

        return scanner.scan()

    def render(self, outfd):
        outfd.write("{0:10} {1:10} {2}\n".format("Offset(V)", "Offset(P)", "Name"))
        for phive in self.generate_hits():
            # Make the hive in the kernel address space by reflecting through
            # the HiveList. Note that this may not return to the original
            # object!
            hive = phive.HiveList.reflect(vm=self.kernel_address_space).dereference_as(
                "_CMHIVE", "HiveList")

            outfd.write("{0:#010x} {1:#010x} {2}\n".format(
                    hive.obj_offset, phive.obj_offset, hive.Name))
