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

from rekall.plugins.common import entities


class DarwinOnlyMixin(object):
    @classmethod
    def is_active(cls, session):
        """Only active for Darwin right now."""
        return (session.profile.metadata("os") == "darwin" and
                plugin.Command.is_active(session))


class ListZones(entities.EntityFind):
    __name = "zones"
    search = "has component AllocationZone"
    columns = ["AllocationZone/name", "AllocationZone/count_active",
               "AllocationZone/count_free", "AllocationZone/element_size",
               "AllocationZone/tracks_pages", "AllocationZone/allows_foreign"]
    sort = ["AllocationZone/name"]


class ListEvents(entities.EntityFind):
    __name = "events"
    search = "has component Event"
    columns=["Event/timestamp", "Event/category", "Event/actor",
             "Event/action", "Event/target"]
    sort=["Event/timestamp", "Event/category", "Event/action"]


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
              "has component MemoryObject) "
              "and Handle/process->Process/user matches "
              "(has component User)")
    columns = ["Handle/process", "Handle/process->Process/user", "Handle/fd",
               "Handle/resource->Named/kind", "Handle/resource"]
    sort = ["Handle/process->Process/pid", "Handle/fd"]


class IPNetstat(entities.EntityFind):
    __name = "ipnetstat"
    description = "IP Connections"
    width = 150
    search = "OSILayer3/protocol in (IPv4, IPv6) and has component OSILayer4"
    columns = ["OSILayer3/protocol", "OSILayer4/protocol",
               "OSILayer3/src_addr", "OSILayer4/src_port",
               "OSILayer3/dst_addr", "OSILayer4/dst_port",
               "OSILayer4/state", "Connection/handles->Handle/process"]
    sort = ["OSILayer3/protocol", "OSILayer4/protocol", "OSILayer3/src_addr"]


class SocketNetstat(DarwinOnlyMixin, entities.EntityFind):
    __name = "unix_sockets"
    description = "UNIX sockets"
    search = "Connection/protocol_family is UNIX"
    columns=["Socket/type", "Socket/address", "Socket/connected",
             "Socket/file", "Connection/handles->Handle/process"]
    sort = ["Socket/address"]


class EntityNetstat(DarwinOnlyMixin, entities.FindBatch):
    __name = "netstat"
    batch = ["ipnetstat", "unix_sockets"]
