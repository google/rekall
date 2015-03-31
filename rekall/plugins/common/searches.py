# Rekall Memory Forensics
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

"""Various plugins that make entities testable and easier to profile."""

__author__ = "Adam Sindelar <adamsh@google.com>"


from rekall import plugin
from rekall import testlib

from rekall.plugins.common import entities


class DarwinOnlyMixin(object):
    @classmethod
    def is_active(cls, session):
        """Only active for Darwin right now."""
        return (session.profile.metadata("os") == "darwin" and
                plugin.Command.is_active(session))


class ListInterfaces(DarwinOnlyMixin, entities.EntityFind):
    name = "ifconfig"
    search = "has component NetworkInterface"

    columns = ["NetworkInterface/name",
               "NetworkInterface/endpoints->OSILayer2/address",
               "NetworkInterface/endpoints->OSILayer3/address"]

    sort = ["Endpoint/owner->NetworkInterface/name",
            "OSILayer3/protocol",
            "OSILayer3/address"]


class ListZones(entities.EntityFind):
    name = "zones"
    search = "has component AllocationZone"
    columns = ["AllocationZone/name", "AllocationZone/count_active",
               "AllocationZone/count_free", "AllocationZone/element_size",
               "AllocationZone/tracks_pages", "AllocationZone/allows_foreign"]
    sort = ["AllocationZone/name"]


class TestListZones(testlib.SortedComparison):
    PARAMETERS = dict(commandline="zones")


class ListEvents(entities.EntityFind):
    name = "events"
    search = "has component Event"
    columns = ["Event/timestamp", "Event/category", "Event/actor",
               "Event/action", "Event/target"]
    sort = ["Event/timestamp", "Event/category", "Event/action",
            "Event/actor", "Event/target"]


class TestListEvents(testlib.SortedComparison):
    PARAMETERS = dict(commandline="events")


class Processes(DarwinOnlyMixin, entities.EntityFind):
    __name = "pslist"
    search = ("has component Process")
    columns = ["Process/command", "Process/pid", "Process/parent",
               "Process/user", "Process/is_64bit", "Timestamps/created_at",
               "Process/cr3"]
    sort = ["Process/pid"]


class LSOF(DarwinOnlyMixin, entities.EntityFind):
    __name = "lsof"
    description = "Open Files"
    width = 150
    search = ("Handle/resource matches "
              "(has component File or has component Connection or "
              "has component Struct) "
              "and Handle/process->Process/user matches "
              "(has component User)")
    columns = ["Handle/process", "Handle/process->Process/user", "Handle/fd",
               "Handle/resource->Named/kind", "Handle/resource"]
    sort = ["Handle/process->Process/pid", "Handle/fd"]


class DarwinListFiles(DarwinOnlyMixin, entities.EntityFind):
    __name = "list_files"
    description = "All Files"
    width = 110
    search = "has component File"
    columns = [dict(width=10, attribute="File/type"),
               dict(name="Sources",
                    fn=lambda e: ",".join(sorted(e["Entity/collectors"])),
                    width=30),
               dict(name="Created", width=15,
                    attribute="Timestamps/created_at"),
               dict(name="Modified", width=15,
                    attribute="Timestamps/modified_at"),
               dict(attribute="File/path", width=40)]
    sort = ["Timestamps/created_at", "Timestamps/modified_at"]


class TestDarwinListFiles(testlib.SortedComparison):
    PARAMETERS = dict(commandline="list_files")


class IPNetstat(entities.EntityFind):
    __name = "ipnetstat"
    description = "IP Connections"
    width = 150
    search = "Connection/protocol_family in ('INET', 'INET6')"
    columns = [dict(name="protocol",
                    fn=lambda e: "/".join([
                        e["Connection/source->OSILayer3/protocol"],
                        e["Connection/source->OSILayer4/protocol"]])),
               dict(attribute="Connection/source->OSILayer3/address",
                    name="src address"),
               dict(attribute="Connection/source->OSILayer4/port",
                    name="src port"),
               dict(attribute="Connection/destination->OSILayer3/address",
                    name="dst address"),
               dict(attribute="Connection/destination->OSILayer4/port",
                    name="dst port"),
               "Connection/source->OSILayer4/state",
               "Connection/handles->Handle/process"]
    sort = ["Connection/source->OSILayer3/protocol",
            "Connection/source->OSILayer4/protocol",
            "Connection/destination->OSILayer3/address",
            "Connection/destination->OSILayer4/port",
            "Connection/source->OSILayer3/address",
            "Connection/source->OSILayer4/port"]


class SocketNetstat(DarwinOnlyMixin, entities.EntityFind):
    __name = "unix_sockets"
    description = "UNIX sockets"
    search = "Connection/protocol_family is 'UNIX'"
    columns = ["Socket/type", "Socket/address", "Socket/connected",
               "Socket/file", "Connection/handles->Handle/process"]
    sort = ["Socket/address"]


class EntityNetstat(DarwinOnlyMixin, entities.FindBatch):
    __name = "netstat"
    batch = ["ipnetstat", "unix_sockets"]
