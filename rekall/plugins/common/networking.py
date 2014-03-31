# Rekall Memory Forensics
#
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

"""
Networking plugins that are not OS-specific live here.
"""
__author__ = "Adam Sindelar <adamsh@google.com>"

from rekall import entity
from rekall import plugin


class EntityIFConfig(plugin.ProfileCommand):
    """List active network interfaces and their addresses."""

    __name = "eifconfig"

    def render(self, renderer):
        renderer.table_header([("Interface", "interface", "10"),
                               ("Family", "af", "10"),
                               ("Address", "address", "20")])

        for interface in self.session.entities.find(
            entity_cls=entity.NetworkInterface):
            for address in interface.addresses:
                renderer.table_row(
                    interface.interface_name,
                    address[0],
                    address[1],
                )


class EntityNetstat(plugin.ProfileCommand):
    """List per process network connections."""

    __name = "enetstat"

    def render(self, renderer):
        # Group connections by protocol and addressing family.
        inet_by_proto = {}
        unix_socks = []

        for connection in self.session.entities.find(
            entity_cls=entity.Connection):
            if connection.addressing_family in ["AF_INET", "AF_INET6"]:
                proto = connection.protocol
                for handle in connection.handles:
                    row = (
                        proto,
                        connection.src_address,
                        connection.src_port,
                        connection.dst_address,
                        connection.dst_port,
                        connection.state,
                        handle.process.pid,
                        handle.process.command,
                    )
                    inet_by_proto.setdefault(proto, []).append(row)
            elif connection.addressing_family == "AF_UNIX":
                for handle in connection.handles:
                    row = (
                        connection.source,
                        connection.destination,
                        connection.entity_type,
                        "0x%x" % int(connection.key_obj.vnode),
                        connection.entity_name,
                        handle.process.pid,
                        handle.process.command,
                    )
                    unix_socks.append(row)

        # First, render internet connections.
        renderer.section("Active Internet connections")
        renderer.table_header([
            ("Proto", "proto", "14"),
            ("SAddr", "saddr", "30"),
            ("SPort", "sport", "8"),
            ("DAddr", "daddr", "30"),
            ("DPort", "dport", "5"),
            ("State", "state", "15"),
            ("Pid", "pid", "8"),
            ("Comm", "comm", "20"),
        ])

        # Sort by inet protos, then PID.
        for proto, rows in sorted(inet_by_proto.iteritems()):
            for row in sorted(rows, key=lambda row: row[-2]):
                renderer.table_row(*row)

        # Render the UNIX sockets.
        renderer.section("Active UNIX domain sockets")
        renderer.table_header([
            ("Address", "address", "14"),
            ("Conn", "conn", "14"),
            ("Type", "type", "10"),
            ("Vnode", "vnode", "14"),
            ("Path", "path", "60"),
            ("Pid", "pid", "8"),
            ("Comm", "comm", "20"),
        ])

        for row in sorted(unix_socks, key=lambda row: row[-2]):
            renderer.table_row(*row)

