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
This module defines all the components that Rekall knows about.

A component is a collection of properties that relate to an entity, which is
an encapsulated notion of identity. In Rekall, components are basically just
named tuples which we store in a big hashtable, indexed by the entity they
relate to.

See:
  http://en.wikipedia.org/wiki/Entity_component_system
"""
__author__ = "Adam Sindelar <adamsh@google.com>"

import collections

from rekall import superposition


COMPONENTS = [
    "Entity",  # Has to be first!
    "Named",
    "MemoryObject",
    "NetworkInterface",
    "Process",
    "Thread",
    "Connection",
    "Handle",
    "File",
    "User",
    "Group",
#    "Timer",
#    "Route",
#    "LoginSession",
#    "KernelModule",
#    "Mount",
#    "AllocationZone",
]


class ComponentTuple(collections.namedtuple("ComponentTuple", COMPONENTS)):
    """Has a property named after every component defined in this module."""

    def union(self, other):
        components = [
            superposition.SuperpositionMergeNamedTuples(
                getattr(self, component),
                getattr(other, component),
            )
            for component in COMPONENTS[1:]  # Skip Entity.
        ]

        # Entity is merged using slightly simpler rules.
        entity = Entity(
            identity=self.Entity.identity | other.Entity.identity,
            collectors=self.Entity.collectors | other.Entity.collectors,
        )

        return ComponentTuple(
            entity,
            *components
        )

    def __or__(self, other):
        return self.union(other)


__EmptyComponentTuple = ComponentTuple(*[None for _ in COMPONENTS])


def MakeComponentTuple(*components):
    kwargs = {}
    for component in components:
        name = type(component).__name__
        kwargs[name] = component

    return __EmptyComponentTuple._replace(**kwargs)

# Special component that the entity system uses to store identifying
# information. This is kept in a component for ease of access, serialization and
# consistency reasons.
Entity = collections.namedtuple(
    "Entity",
    ["identity", "collectors"],
)


Named = collections.namedtuple(
    "Named",
    ["name", "kind"],
)


MemoryObject = collections.namedtuple(
    "MemoryObject",
    ["base_object", "type"],
)


NetworkInterface = collections.namedtuple(
    "NetworkInterface",
    ["addresses"],
)


Process = collections.namedtuple(
    "Process",
    ["pid", "parent", "user", "command", "arguments"],
)


Thread = collections.namedtuple(
    "Thread",
    ["state"],
)


Connection = collections.namedtuple(
    "Connection",
    [
        "src_addr",
        "dst_addr",
        "protocols",  # Known protocols, in order (e.g. [IPv4, TCP])
        "addressing_family",  # Addressing protocol family (e.g. INET or UNIX)
        "state",  # State of the connection, if meaningful.
        "src_bind",  # Source port for inet, vnode for unix, etc.
        "dst_bind",
    ],
)


Handle = collections.namedtuple(
    "Handle",
    ["resource", "process", "fd", "flags"],
)


File = collections.namedtuple(
    "File",
    ["full_path"],
)


User = collections.namedtuple(
    "User",
    ["uid", "home_dir", "username", "real_name"],
)


Group = collections.namedtuple(
    "Group",
    ["gid", "group_name"],
)


# Timer = collections.namedtuple(
#     "Timer",
#     [],
# )
#
#
# Route = collections.namedtuple(
#     "Route",
#     ["source", "destination", "interface"],
# )
#
#
# LoginSession = collections.namedtuple(
#     "LoginSession",
#     ["user", "timestamp"],
# )
#
#
# KernelModule = collections.namedtuple(
#     "KernelModule",
#     [],
# )
#
#
# Mount = collections.namedtuple(
#     "Mount",
#     [],
# )
#
#
# AllocationZone = collections.namedtuple(
#     "AllocationZone",
#     [],
# )
#
