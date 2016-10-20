# Rekall Memory Forensics
# Copyright (C) 2008 Volatile Systems
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
This module implements the fast connection scanning

@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com,bdolangavitt@wesleyan.edu
@organization: Volatile Systems
"""

# pylint: disable=protected-access
from rekall import plugin
from rekall.plugins.overlays.windows import tcpip_vtypes
from rekall.plugins.windows import common


class PoolScanConnFast(common.PoolScanner):
    checks = [('PoolTagCheck', dict(tag="TCPT")),
              ('CheckPoolSize', dict(condition=lambda x: x >= 0x198)),
              ('CheckPoolType', dict(non_paged=True, paged=True, free=True)),
              ('CheckPoolIndex', dict(value=0))]


class ConnScan(tcpip_vtypes.TcpipPluginMixin,
               common.WinScanner,
               common.AbstractWindowsCommandPlugin):
    """ Scan Physical memory for _TCPT_OBJECT objects (tcp connections)
    """

    __name = "connscan"

    table_header = [
        dict(name="offset_p", style="address"),
        dict(name="local_net_address", align="l", width=25),
        dict(name="remote_net_address", align="l", width=25),
        dict(name="pid", width=10, align="r")
    ]

    scanner_defaults = dict(
        scan_physical=True
    )

    mode = "mode_xp"

    def column_types(self):
        tcp_obj = self.tcpip_profile._TCPT_OBJECT()
        return dict(offset_p=tcp_obj,
                    local_net_address="172.16.176.143:1034",
                    remote_net_address="131.107.115.254:80",
                    pid=tcp_obj.Pid)

    def collect(self):
        """Search the physical address space for _TCPT_OBJECTs.

        Yields:
          _TCPT_OBJECT instantiated on the physical address space.
        """
        for run in self.generate_memory_ranges():
            # The pool is managed by the kernel so we need to use the kernel's
            # profile here.
            scanner = PoolScanConnFast(
                session=self.session, profile=self.profile,
                address_space=run.address_space)

            for pool_obj in scanner.scan(run.start, maxlen=run.length):
                # The struct is allocated out of the pool (i.e. its not an
                # object).
                tcp_obj = self.tcpip_profile._TCPT_OBJECT(
                    vm=run.address_space,
                    offset=pool_obj.obj_offset + pool_obj.obj_size)

                local = "{0}:{1}".format(tcp_obj.LocalIpAddress,
                                         tcp_obj.LocalPort)

                remote = "{0}:{1}".format(tcp_obj.RemoteIpAddress,
                                          tcp_obj.RemotePort)

                yield tcp_obj, local, remote, tcp_obj.Pid
