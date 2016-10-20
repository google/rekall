# Rekall Memory Forensics
#
# Copyright 2014 Google Inc. All Rights Reserved.
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

"""This module extracts network information using kernel object inspection.

The netscan plugins use pool tags to scan for objects, while this file directly
examines kernel data structures.
"""

__author__ = "Michael Cohen <scudette@google.com>"


from rekall.plugins.windows import common
from rekall.plugins.overlays.windows import tcpip_vtypes



class WinNetstat(tcpip_vtypes.TcpipPluginMixin, common.WindowsCommandPlugin):
    """Enumerate image for connections and sockets"""

    __name = "netstat"

    table_header = [
        dict(name="offset", style="address"),
        dict(name="protocol", width=8),
        dict(name="local_addr", width=20),
        dict(name="remote_addr", width=20),
        dict(name="state", width=16),
        dict(name="pid", width=5, align="r"),
        dict(name="owner", width=14),
        dict(name="created", width=7)
    ]

    @classmethod
    def is_active(cls, session):
        # This plugin works with the _TCP_ENDPOINT interfaces. This interface
        # uses the new HashTable entry in ntoskernl.exe.
        return (super(WinNetstat, cls).is_active(session) and
                session.profile.get_constant('RtlEnumerateEntryHashTable'))

    def collect(self):
        # First list established endpoints (TcpE pooltags).
        partition_table = self.tcpip_profile.get_constant_object(
            "PartitionTable",
            target="Pointer",
            target_args=dict(
                target="PARTITION_TABLE",
                )
            )

        for partition in partition_table.Partitions:
            for first_level in partition:
                for second_level in first_level.SecondLevel:
                    for endpoint in second_level.list_of_type(
                            "_TCP_ENDPOINT", "ListEntry"):

                        lendpoint = "{0}:{1}".format(
                            endpoint.LocalAddress(),
                            endpoint.LocalPort)

                        rendpoint = "{0}:{1}".format(
                            endpoint.RemoteAddress(),
                            endpoint.RemotePort)

                        yield dict(offset=endpoint,
                                   protocol=None,
                                   local_addr=lendpoint,
                                   remote_addr=rendpoint,
                                   state=endpoint.State,
                                   pid=endpoint.Owner.pid,
                                   owner=endpoint.Owner.name,
                                   created=endpoint.CreateTime)
