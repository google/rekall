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
This module implements the fast connection scanning

@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com,bdolangavitt@wesleyan.edu
@organization: Volatile Systems
"""

from volatility.plugins.windows import common


class PoolScanConnFast(common.PoolScanner):
    checks = [ ('PoolTagCheck', dict(tag = "TCPT")),
               ('CheckPoolSize', dict(condition = lambda x: x >= 0x198)),
               ('CheckPoolType', dict(non_paged = True, free = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ]

class ConnScan(common.AbstractWindowsCommandPlugin):
    """ Scan Physical memory for _TCPT_OBJECT objects (tcp connections)
    """
    meta_info = dict(
        author = 'Brendan Dolan-Gavitt',
        copyright = 'Copyright (c) 2007,2008 Brendan Dolan-Gavitt',
        contact = 'bdolangavitt@wesleyan.edu',
        license = 'GNU General Public License 2.0 or later',
        url = 'http://moyix.blogspot.com/',
        os = 'WIN_32_XP_SP2',
        version = '1.0',
        )

    __name = "connscan"

    def generate_hits(self):
        """Search the physical address space for _TCPT_OBJECTs.

        Yields:
          _TCPT_OBJECT instantiated on the physical address space.
        """
        scanner = PoolScanConnFast(
            profile=self.profile, address_space=self.physical_address_space)

        for offset in scanner.scan():
            ## The struct is allocated out of the pool (i.e. its not an object).
            yield scanner.get_allocation(offset, "_TCPT_OBJECT")

    def render(self, renderer):
        renderer.table_header([("Offset(P)", "[addrpad]"),
                               ("Local Address", "<25"),
                               ("Remote Address", "<25"),
                               ("Pid", ">10")])

        ## We make a new scanner
        for tcp_obj in self.generate_hits():
            local = "{0}:{1}".format(tcp_obj.LocalIpAddress, tcp_obj.LocalPort)
            remote = "{0}:{1}".format(tcp_obj.RemoteIpAddress, tcp_obj.RemotePort)
            renderer.table_row(tcp_obj.obj_offset, local, remote, tcp_obj.Pid)
