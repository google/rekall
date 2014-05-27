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

from rekall import plugin


class EntityIFConfig(plugin.ProfileCommand):
    """List active network interfaces and their addresses."""

    __name = "eifconfig"

    def render(self, renderer):
        renderer.table_header([("Interface", "interface", "10"),
                               ("Family", "af", "10"),
                               ("Address", "address", "20")],
                              sort=("interface",))

        for interface in self.session.entities.find_by_component(
            component="NetworkInterface",
        ):
            for address in interface.components.NetworkInterface.addresses:
                renderer.table_row(
                    interface.components.Named.name,
                    address[0],
                    address[1],
                )


class EntityNetstat(plugin.ProfileCommand):
    """List per process network connections."""

    __name = "enetstat"

    def render(self, renderer):
        entities = self.session.entities.find_by_component("Connection")

        # Sort all the sockets into buckets based on whether they're network or
        # UNIX connections.
        inet_socks = []
        unix_socks = []

        for entity in entities:
            af = entity["Connection.addressing_family"]
            if af in ("AF_INET", "AF_INET6"):
                # Inet socket.
                row = [
                    entity["Connection.protocols"][1],
                    entity["Connection.src_addr"],
                    entity["Connection.src_bind"],
                    entity["Connection.dst_addr"],
                    entity["Connection.dst_bind"],
                    entity["Connection.state"],
                ]

                bucket = inet_socks
            elif af == "AF_UNIX":
                # Unix socket
                row = [
                    entity["Connection.src_addr"],
                    entity["Connection.dst_addr"],
                    entity["Connection.protocols"][1],
                    entity["Connection.src_bind"],
                ]

                bucket = unix_socks
            else:
                continue  # Don't care.

            # A single socket can be open by 1 (most common), 0 or multiple
            # handles (fds) owned by one or more processes.
            handles = list(entity.get_referencing_entities("Handle.resource"))
            for handle in handles:
                proc = handle["Handle.process"]
                bucket.append(row + proc["Process.pid", "Process.command"])

            if not handles:
                # No process has a handle on this.
                bucket.append(row + [None, None])

        # First, render internet connections.
        renderer.section("Active Internet connections")
        renderer.table_header(
            columns=[
                ("Proto", "proto", "14"),
                ("SAddr", "saddr", "30"),
                ("SPort", "sport", "8"),
                ("DAddr", "daddr", "30"),
                ("DPort", "dport", "5"),
                ("State", "state", "15"),
                ("Pid", "pid", "8"),
                ("Comm", "comm", "20"),
            ],
            sort=("pid", "proto", "saddr", "sport", "daddr", "dport", "state"),
        )

        for row in inet_socks:
            renderer.table_row(*row)

        # Render the UNIX sockets.
        renderer.section("Active UNIX domain sockets")
        renderer.table_header(
            columns=[
                ("Address", "address", "14"),
                ("Conn", "conn", "14"),
                ("Type", "type", "10"),
                ("Path", "path", "60"),
                ("Pid", "pid", "8"),
                ("Comm", "comm", "20"),
            ],
            sort=("pid", "address"),
        )

        for row in unix_socks:
            renderer.table_row(*row)
