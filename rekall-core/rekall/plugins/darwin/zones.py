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
Collectors and plugins that deal with Darwin zone allocator.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

from rekall import plugin
from rekall import utils

from rekall.plugins.darwin import common


class DarwinZoneHook(common.AbstractDarwinParameterHook):
    """Lists all allocation zones."""

    name = "zones"

    def calculate(self):
        first_zone = self.session.profile.get_constant_object(
            "_first_zone",
            target="Pointer",
            target_args=dict(
                target="zone"))

        return [x.obj_offset for x in first_zone.walk_list("next_zone")]


class DarwinZoneCollector(common.AbstractDarwinCachedProducer):
    name = "zones"
    type_name = "zone"


class AbstractZoneElementFinder(common.AbstractDarwinParameterHook):
    """Finds all the valid structs in an allocation zone."""

    __abstract = True

    zone_name = None
    type_name = None

    def validate_element(self, element):
        raise NotImplementedError("Subclasses must override.")

    def calculate(self):
        # Find the zone that contains our data.
        zone = self.session.plugins.search(
            "(select zone from zones() where zone.name == ?).zone",
            query_parameters=[self.zone_name]).first_result

        if zone is None:
            raise ValueError("Zone %r doesn't exist." % self.zone_name)

        results = set()
        for offset in zone.known_offsets:
            element = self.session.profile.Object(offset=offset,
                                                  type_name=self.type_name)

            if self.validate_element(element):
                results.add(element.obj_offset)

        return results


class DarwinDumpZone(common.AbstractDarwinCommand):
    """Dumps an allocation zone's contents."""

    name = "dump_zone"

    table_header = [
        dict(name="offset", style="address"),
        dict(name="data", width=34)
    ]

    @classmethod
    def args(cls, parser):
        super(DarwinDumpZone, cls).args(parser)
        parser.add_argument("--zone", default="buf.512")

    def __init__(self, zone="buf.512", **kwargs):
        super(DarwinDumpZone, self).__init__(**kwargs)
        self.zone_name = zone

    def collect(self):
        zone = self.session.plugins.search(
            "(select zone from zones() where zone.name == {zone_name}).zone",
            query_parameters=dict(zone_name=self.zone_name),
            silent=True
        ).first_result

        if not zone:
            raise ValueError("No such zone %r." % self.zone_name)

        for offset in zone.known_offsets:
            yield dict(offset=offset,
                       data=utils.HexDumpedString(
                           zone.obj_vm.read(offset, zone.elem_size)))


# All plugins below dump and validate elements from specific zones.


class DarwinSocketZoneFinder(AbstractZoneElementFinder):
    name = "dead_sockets"
    zone_name = "socket"
    type_name = "socket"

    def validate_element(self, socket):
        return socket == socket.so_rcv.sb_so


class DarwinSocketZoneCollector(common.AbstractDarwinCachedProducer):
    name = "dead_sockets"
    type_name = "socket"


class DarwinTTYZoneFinder(AbstractZoneElementFinder):
    name = "dead_ttys"
    zone_name = "ttys"
    type_name = "tty"

    def validate_element(self, tty):
        return tty.t_lock == tty


class DarwinTTYZoneCollector(common.AbstractDarwinCachedProducer):
    name = "dead_ttys"
    type_name = "tty"


class DarwinSessionZoneFinder(AbstractZoneElementFinder):
    name = "dead_sessions"
    zone_name = "session"
    type_name = "session"

    def validate_element(self, session):
        return session.s_count > 0 and session.s_leader.p_argc > 0


class DarwinSessionZoneCollector(common.AbstractDarwinCachedProducer):
    name = "dead_sessions"
    type_name = "session"


class DarwinZoneVnodeFinder(AbstractZoneElementFinder):
    zone_name = "vnodes"
    type_name = "vnode"
    name = "dead_vnodes"

    def validate_element(self, vnode):
        # Note for later: HFS-related vnodes can be validated
        # by the pointer they have back to the vnode from the cnode (v_data).
        return vnode.v_owner == 0 and vnode.v_mount != 0


class DarwinZoneVnodeCollector(common.AbstractDarwinCachedProducer):
    name = "dead_vnodes"
    type_name = "vnode"


class PsListDeadProcFinder(AbstractZoneElementFinder):
    name = "dead_procs"
    zone_name = "proc"
    type_name = "proc"

    def validate_element(self, element):
        return element.validate()


class DarwinDeadProcessCollector(common.AbstractDarwinCachedProducer):
    """Lists dead processes using the proc allocation zone."""
    name = "dead_procs"
    type_name = "proc"


class DarwinZoneFileprocFinder(AbstractZoneElementFinder):
    name = "dead_fileprocs"
    type_name = "fileproc"
    zone_name = "fileproc"

    def validate_element(self, element):
        return True


class DarwinDeadFileprocCollector(common.AbstractDarwinCachedProducer):
    name = "dead_fileprocs"
    type_name = "fileproc"
