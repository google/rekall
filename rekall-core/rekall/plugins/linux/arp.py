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
@author:       Andrew Case
@license:      GNU General Public License 2.0 or later
@contact:      atcuno@gmail.com
@organization: Digital Forensics Solutions
"""
from rekall import obj
from rekall.plugins.linux import common


arp_overlay = {
    'neigh_table': [None, {
        # From /include/linux/socket.h
        'family': [None, ['Enumeration', dict(
            choices={
                0: "AF_UNSPEC",
                1: "AF_UNIX",
                2: "AF_INET",
                10: "AF_INET6",
                },
            target="unsigned int",
            )]]
        }],
    'neighbour': [None, {
        "ha": [None, ["Array", dict(
            target="byte",
            count=lambda x: x.dev.addr_len)]],
        }],
    }


class ArpModification(obj.ProfileModification):
    @classmethod
    def modify(cls, profile):
        profile.add_overlay(arp_overlay)


class Arp(common.LinuxPlugin):
    """print the ARP table."""

    # This plugin seems broken now.
    __name = "arp"

    table_header = [
        dict(name="ip", width=45, align="r"),
        dict(name="mac", width=20, align="r"),
        dict(name="dev", width=15, align="r")
    ]

    def __init__(self, **kwargs):
        super(Arp, self).__init__(**kwargs)
        self.profile = ArpModification(self.profile)

    def get_handle_tables(self):
        # In earlier Linux neigh_table is a linked list.
        if self.session.profile.neigh_table().m("next") != None:
            tables = self.profile.get_constant_object(
                "neigh_tables",
                target="Pointer",
                target_args=dict(
                    target="neigh_table"
                    )
                )

            for table in tables.walk_list("next"):
                for x in self.handle_table(table):
                    yield x

        # But since 3.19 it is an array of pointers to neigh_tables.
        # http://lxr.free-electrons.com/source/net/core/neighbour.c?v=3.19#L1517
        # static struct neigh_table *neigh_tables[NEIGH_NR_TABLES]
        # NEIGH_NR_TABLES is in an enum and it is 3.
        else:
            tables = self.profile.get_constant_object(
                "neigh_tables",
                target="Array",
                target_args=dict(
                    target="Pointer",
                    count=3,
                    target_args=dict(
                        target="neigh_table"
                    )
                )
            )

            for table in tables:
                for x in self.handle_table(table):
                    yield x

    def handle_table(self, ntable):
        # Support a few ways of finding these parameters depending on kernel
        # versions.
        hash_size = (ntable.m("hash_mask") or
                     ntable.nht.m("hash_mask") or
                     1 << ntable.nht.hash_shift)

        hash_table = ntable.m("hash_buckets") or ntable.nht.hash_buckets

        buckets = self.profile.Array(offset=hash_table,
                                     vm=self.kernel_address_space,
                                     target='Pointer', count=hash_size,
                                     target_args=dict(target="neighbour"))

        for neighbour in buckets:
            if neighbour:
                for x in self.walk_neighbour(neighbour.deref()):
                    yield x

    def walk_neighbour(self, neighbour):
        while 1:
            # get the family from each neighbour in order to work with IPv4 and
            # IPv6.
            family = neighbour.tbl.family

            if family == "AF_INET":
                ip = neighbour.primary_key.cast("Ipv4Address")

            elif family == "AF_INET6":
                ip = neighbour.primary_key.cast("Ipv6Address")
            else:
                ip = '?'

            mac = ":".join(["%.02x" % x for x in neighbour.ha])
            devname = neighbour.dev.name

            yield dict(ip=ip, mac=mac, dev=devname)

            neighbour = neighbour.next.deref()

            if not neighbour:
                break

    def collect(self):
        for x in self.get_handle_tables():
            yield x
