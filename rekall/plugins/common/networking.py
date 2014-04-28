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
        
        inet_socks = []
        unix_socks = []

        def unix_row(connection, process):
            if process:
                pid, comm = process["Process.pid"], process["Process.command"]
            else:
                pid, comm = None, None

            unix_socks.append((
                connection.src_addr,
                connection.dst_addr,
                connection.protocols[1],
                connection.src_bind,
                pid,
                comm,
            ))

        def inet_row(connection, process):
            if process:
                pid, comm = process["Process.pid"], process["Process.command"]
            else:
                pid, comm = None, None

            inet_socks.append((
                connection.protocols[1],
                connection.src_addr,
                connection.src_bind,
                connection.dst_addr,
                connection.dst_bind,
                connection.state,
                pid,
                comm,
            ))

        for entity in entities:
            connection = entity.components.Connection
            if connection.addressing_family in ("AF_INET", "AF_INET6"):
                row_func = inet_row
            elif connection.addressing_family == "AF_UNIX":
                row_func = unix_row
            else:
                continue  # So not interested...

            handles = list(entity.get_related_entities("Resource.handle"))

            if not handles:
                # No process has a handle on this socket. Print it anyway.
                row_func(connection, None)
                continue
            
            for handle in handles:
                # At least one process has a handle on this.
                for p in handle.get_related_entities("Handle.process"):
                    process = p

                row_func(connection, process)

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

