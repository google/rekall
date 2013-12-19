# Rekall Memory Forensics
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
#

__author__ = "Michael Cohen <scudette@gmail.com>"

"""Implement OSX support."""

import socket

from rekall import obj
from rekall.plugins.overlays import basic

darwin_overlay = {
    "proc": [None, {
            "p_list": [None, ["LIST_ENTRY"]],
            "p_sibling": [None, ["LIST_ENTRY"]],

            "p_comm": [None, ["String"]],
            "task": [None, ["Pointer", dict(
                        target="task"
                        )]],
            }],
    "task": [None, {
            "bsd_info": [None, ["Pointer", dict(target="proc")]],
            }],

    "rtentry": [None, {
            "base_calendartime": [None, ["UnixTimeStamp"]],

            "source_ip": lambda x: x.rt_nodes[0].rn_u.rn_leaf.m(
                "rn_Key").dereference_as("sockaddr"),

            "dest_ip": lambda x: x.rt_gateway.deref(),

            "name": lambda x: "%s%s" % (
                x.rt_ifp.if_name.dereference_as("String"),
                x.rt_ifp.if_unit),

            "sent": lambda x: x.m("rt_stats").nstat_txpackets,

            "rx": lambda x: x.rt_expire if x.m("rt_stats") else None,

            "delta": lambda x: (x.rt_expire - x.base_uptime
                                if x.rt_expire else 0),

            }],

    "kmod_info": [None, {
            "name": [None, ["String"]],
            "version": [None, ["String"]],

            # Starting address of the kernel module.
            "address": [None, ["Pointer"]],
            }],

    "sockaddr": [None, {
            # bsd/sys/socket.h: 371
            'sa_family': [None, ["Enumeration", dict(
                        choices={
                            1: "AF_UNIX",
                            2: "AF_INET",
                            18: "AF_LINK",
                            30: "AF_INET6",
                            },
                        target="unsigned char",
                        )]],
            }],

    "sysctl_oid": [None, {
            # xnu-2422.1.72/bsd/sys/sysctl.h: 148
            # This field is reused for two purposes, the first is type of node,
            # while the second is the permissions.
            "oid_kind_type": lambda x: x.m("oid_kind").cast(
                "Enumeration", choices={
                    1: "CTLTYPE_NODE",
                    2: "CTLTYPE_INT",
                    3: "CTLTYPE_STRING",
                    4: "CTLTYPE_QUAD",
                    5: "CTLTYPE_OPAQUE",
                    },
                target="BitField",
                target_args=dict(start_bit=0, end_bit=8),
                ),

            "oid_perms": lambda x: x.m("oid_kind").cast(
                "Flags", maskmap={
                    "CTLFLAG_RD": 0x80000000, # Allow reads of variable */
                    "CTLFLAG_WR": 0x40000000, # Allow writes to the variable
                    "CTLFLAG_LOCKED": 0x00800000, # node will handle locking itself
                    },
                ),

            "oid_name": [None, ["Pointer", dict(target="String")]],

            }],
    }


darwin64_types = {
    "LIST_ENTRY": [16, {
            "le_next": [0, ["Pointer"]],
            "le_prev": [8, ["Pointer", dict(target="Pointer")]],
            }],
    }


class LIST_ENTRY(obj.Struct):
    """XNU defines lists inline using an annonymous struct. This makes it hard
    for us to automatically support lists because the debugging symbols dont
    indicate this inner struct is of any particular type( since its annonymous).

    We therefore depend on the overlays to redefine each list memeber as a
    LIST_ENTRY member. For example we see code like:

    struct proc {
       LIST_ENTRY(proc) p_list;
       ...

    Where:

    #define  LIST_ENTRY(type)                                       \
      struct {                                                      \
      struct type *le_next;  /* next element */                     \
      struct type **le_prev; /* address of previous next element */ \
    }
    """
    _forward = "le_next"
    _backward = "le_prev"

    def is_valid(self):
        """Must have both valid next and prev pointers."""
        return (self.m(self._forward).is_valid() and
                self.m(self._backward).is_valid())

    def _GetNextEntry(self, type, member):
        return self.m(self._forward).dereference_as(type).m(member)

    def _GetPreviousEntry(self):
        return self.m(self._backward).dereference_as(self.obj_type)

    def dereference_as(self, type, member, vm=None):
        """Recasts the list entry as a member in a type, and return the type.

        Args:
        type: The name of this Struct type.
        member: The name of the member of this Struct.
        address_space: An optional address space to switch during
        deferencing.
        """
        offset = self.obj_profile.get_obj_offset(type, member)

        item = self.obj_profile.Object(
            theType=type, offset=self.obj_offset - offset,
            vm=vm or self.obj_vm, parent=self.obj_parent,
            name=type, context=self.obj_context)

        return item

    def find_all_lists(self, type, member, seen=None):
        """Follows all the list entries starting from lst.

        We basically convert the list to a tree and recursively search it for
        new nodes. From each node we follow the Flink and then the Blink. When
        we see a node we already have, we backtrack.
        """
        if seen is None:
            seen = set()

        if not self.is_valid():
            return seen

        elif self in seen:
            return seen

        seen.add(self)

        Flink = self._GetNextEntry(type, member)
        Flink.find_all_lists(type, member, seen=seen)

        # Blink = self._GetPreviousEntry()
        # Blink.find_all_lists(type, member, seen=seen)

        return seen

    def list_of_type(self, type, member=None, include_current=True):
        result = self.find_all_lists(type, member)

        if member is None:
            member = self.obj_name

        # Return ourselves as the first item.
        if include_current:
            yield self.dereference_as(type, member)

        # We traverse all the _LIST_ENTRYs we can find, and cast them all back
        # to the required member.
        for lst in result:
            # Skip ourselves in this (list_of_type is usually invoked on a list
            # head).
            if lst.obj_offset == self.obj_offset:
                continue

            task = lst.dereference_as(type, member)
            if task:
                # Only yield valid objects (In case of dangling links).
                yield task

    def reflect(self, vm=None):
        """Reflect this list element by following its Flink and Blink.

        This is basically the same as Flink.Blink except that it also checks
        Blink.Flink. It also ensures that Flink and Blink are dereferences to
        the correct type in case the vtypes do not specify them as pointers.

        Returns:
        the result of Flink.Blink.
        """
        result1 = self.m(self._forward).dereference_as(
            self.obj_type, vm=vm).m(self._backward).deref().cast(
            self.obj_type)

        if not result1:
            return obj.NoneObject("Flink not valid.")

        result2 = self.Blink.deref().dereference_as(
            self.obj_type, vm=vm).m(
            self._forward).dereference_as(self.obj_type)

        if result1 != result2:
            return obj.NoneObject("Flink and Blink not consistent.")

        return result1

    def __nonzero__(self):
        ## List entries are valid when both Flinks and Blink are valid
        return bool(self.m(self._forward)) or bool(self.m(self._backward))

    def __iter__(self):
        return self.list_of_type(self.obj_parent.obj_type, self.obj_name)


class queue_entry(LIST_ENTRY):
    _forward = "next"
    _backward = "prev"


class sockaddr_dl(obj.Struct):
    def __str__(self):
        result = []
        for i in range(self.sdl_alen):
            result.append(
                "%.02X" % ord(self.sdl_data[self.sdl_nlen + i].v()))

        return ":".join(result)


class sockaddr(obj.Struct):
    def _get_address_obj(self):
        addr = obj.NoneObject("Unknown socket family")

        if self.sa_family == "AF_INET":
            addr = self.cast("sockaddr_in").sin_addr.s_addr

        elif self.sa_family == "AF_INET6":
            addr = self.cast("sockaddr_in6").sin6_addr.__u6_addr

        elif self.sa_family == "AF_LINK":
            addr = self.cast("sockaddr_dl")

        return addr

    def __str__(self):
        result = ""
        addr = self._get_address_obj()
        if addr:
            if self.sa_family in ("AF_INET6", "AF_INET"):
                result = socket.inet_ntoa(
                    addr.obj_vm.read(addr.obj_offset, addr.size()))

            elif self.sa_family == "AF_LINK":
                result = addr

        return str(result)


class Darwin32(basic.Profile32Bits, basic.BasicWindowsClasses):
    """A Darwin profile."""
    _md_os = "darwin"
    _md_memory_model = "32bit"
    _md_type = "Kernel"

    def __init__(self, **kwargs):
        super(Darwin32, self).__init__(**kwargs)
        self.add_classes(dict(
                LIST_ENTRY=LIST_ENTRY, queue_entry=queue_entry,
                sockaddr=sockaddr, sockaddr_dl=sockaddr_dl,
                ))
        self.add_overlay(darwin_overlay)
        self.add_constants(default_text_encoding="utf8")


class Darwin64(basic.ProfileLP64, Darwin32):
    """Support for 64 bit darwin systems."""

    _md_memory_model = "64bit"

    def __init__(self, **kwargs):
        super(Darwin64, self).__init__(**kwargs)

        self.add_types(darwin64_types)

    def get_constant(self, name, is_address=True):
        if is_address:
            shift = self.session.GetParameter("vm_kernel_slide", 0)
        else:
            shift = 0

        return  super(Darwin64, self).get_constant(name) + shift
