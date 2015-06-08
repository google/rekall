# Rekall Memory Forensics
#
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Authors:
# Mike Auty <mike.auty@gmail.com>
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

from rekall.plugins.overlays.windows import tcpip_vtypes
from rekall.plugins.windows import common


class Connections(tcpip_vtypes.TcpipPluginMixin,
                  common.WindowsCommandPlugin):
    """
    Print list of open connections [Windows XP Only]
    ---------------------------------------------

    This module enumerates the active connections from tcpip.sys.

    Note that if you are using a hibernated image this might not work
    because Windows closes all sockets before hibernating. You might
    find it more effective to do conscan instead.

    Active TCP connections are found in a hash table. The Hash table is given by
    the _TCBTable symbol. The size of the hash table is found in the
    _MaxHashTableSize variable.
    """

    __name = "connections"

    @classmethod
    def is_active(cls, session):
        # These only work for XP.
        return (super(Connections, cls).is_active(session) and
                session.profile.metadata("major") == 5)

    def render(self, renderer):
        renderer.table_header(
            [("Offset (V)", "offset_v", "[addrpad]"),
             ("Local Address", "local_net_address", "25"),
             ("Remote Address", "remote_net_address", "25"),
             ("Pid", "pid", ">6")
            ])

        # The _TCBTable is a pointer to the hash table.
        TCBTable = self.tcpip_profile.get_constant_object(
            "TCBTable",
            target="Pointer",
            vm=self.kernel_address_space,
            target_args=dict(
                target="Array",
                target_args=dict(
                    count=int(self.tcpip_profile.get_constant_object(
                        "MaxHashTableSize", "unsigned int")),

                    target="Pointer",
                    target_args=dict(
                        target="_TCPT_OBJECT"
                        )
                    )
                )
            )

        # Walk the hash table and print all the conenctions.
        for slot in TCBTable.deref():
            for conn in slot.walk_list("Next"):
                offset = conn.obj_offset
                local = "{0}:{1}".format(conn.LocalIpAddress, conn.LocalPort)
                remote = "{0}:{1}".format(conn.RemoteIpAddress, conn.RemotePort)
                renderer.table_row(offset, local, remote, conn.Pid)


class Sockets(tcpip_vtypes.TcpipPluginMixin,
              common.WindowsCommandPlugin):
    """
    Print list of open sockets. [Windows xp only]
    ---------------------------------------------

    This module enumerates the active sockets from tcpip.sys

    Note that if you are using a hibernated image this might not work
    because Windows closes all sockets before hibernating.

    _ADDRESS_OBJECT are arranged in a hash table found by the _AddrObjTable
    symbol. The hash table has a size found by the _AddrObjTableSize symbol.
    """

    __name = "sockets"

    @classmethod
    def is_active(cls, session):
        # These only work for XP.
        return (super(Sockets, cls).is_active(session) and
                session.profile.metadata("major") == 5)

    def render(self, renderer):
        renderer.table_header([("Offset (V)", "offset_v", "[addrpad]"),
                               ("PID", "pid", ">6"),
                               ("Port", "port", ">6"),
                               ("Proto", "protocol_number", ">6"),
                               ("Protocol", "protocol", "10"),
                               ("Address", "address", "15"),
                               ("Create Time", "socket_create_time", "")
                              ])

        AddrObjTable = self.tcpip_profile.get_constant_object(
            "AddrObjTable",
            target="Pointer",
            vm=self.kernel_address_space,
            target_args=dict(
                target="Array",
                target_args=dict(
                    count=int(self.tcpip_profile.get_constant_object(
                        "AddrObjTableSize", "unsigned int")),

                    target="Pointer",
                    target_args=dict(
                        target="_ADDRESS_OBJECT"
                        )
                    )
                )
            )

        for slot in AddrObjTable.deref():
            for sock in slot.walk_list("Next"):
                renderer.table_row(
                    sock, sock.Pid, sock.LocalPort,
                    int(sock.Protocol), sock.Protocol,
                    sock.LocalIpAddress, sock.CreateTime)
