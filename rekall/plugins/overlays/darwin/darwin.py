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

from rekall import obj
from rekall import utils
from rekall.plugins.overlays import basic

darwin_overlay = {
    "proc": [None, {
        # Some standard fields for darwin processes.
        'name': lambda x: x.p_comm,
        'pid': lambda x: x.p_pid,

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
    "zone": [None, {
            "zone_name": [None, ["Pointer", dict(target="String")]],
            "free_elements": [None, ["Pointer", dict(
                        target="zone_free_element"
                        )]],
            }],

    "vm_map_entry": [None, {
            # xnu-2422.1.72/osfmk/mach/vm_prot.h:81
            "protection": [None, ["Flags", dict(
                        maskmap={
                            "VM_PROT_READ":    1,
                            "VM_PROT_WRITE":   2,
                            "VM_PROT_EXECUTE": 4,
                            },
                        target="BitField",
                        target_args=dict(
                            start_bit=7,
                            end_bit=10
                            )
                        )]],
            }],

    "vnode": [None, {
            "v_name": [None, ["Pointer", dict(target="String")]],

            "path": lambda self: "/".join(reversed(
                    [unicode(y.v_name.deref())
                     for y in self.walk_list("v_parent")])),

            # xnu-2422.1.72/bsd/sys/vnode_internal.h:230
            "v_flag": [None, ["Flags", dict(
                        maskmap={
                            "VROOT":   0x000001,
                            "VTEXT":   0x000002,
                            "VSYSTEM": 0x000004,
                            "VISTTY":  0x000008,
                            "VRAGE":   0x000010,
                            }
                        )]],
            }],

    "ifnet": [None, {
            "if_name": [None, ["Pointer", dict(target="String")]],
            }],

    "session": [None, {
            "s_login": [None, ["String"]],
            }],

    "filedesc": [None, {
            "fd_ofiles": [None, ["Pointer", dict(
                        target="Array",
                        target_args=dict(
                            target="Pointer",
                            count=lambda x: x.fd_lastfile,
                            target_args=dict(
                                target="fileproc"
                                )
                            )
                        )]],
            }],

    "mount": [None, {
            # xnu-2422.1.72/bsd/sys/mount.h
            "mnt_flag": [None, ["Flags", dict(
                        maskmap={
                            "MNT_LOCAL": 0x00001000,
                            "MNT_QUOTA": 0x00002000,
                            "MNT_ROOTFS": 0x00004000,
                            }
                        )]],
            }],

    "vfsstatfs": [None, {
            "f_mntonname": [None, ["String"]],
            "f_mntfromname": [None, ["String"]],
            "f_fstypename": [None, ["String"]],
            }],

    "sockaddr_un": [None, {
            "sun_path": [None, ["String", dict(
                        length=lambda x: x.sun_len,
                        )]],
            }],

    "domain": [None, {
            # xnu-2422.1.72/bsd/sys/domain.h: 99
            'dom_family': [None, ["Enumeration", dict(
                        choices={
                            1: "AF_UNIX",
                            2: "AF_INET",
                            18: "AF_LINK",
                            30: "AF_INET6",
                            },
                        target="int",
                        )]],
            }],

    "tcpcb": [None, {
            "t_state": [None, ["Enumeration", dict(
                        # xnu-2422.1.72/bsd/netinet/tcp_fsm.h: 75
                        choices={
                            0: "TCPS_CLOSED",
                            1: "TCPS_LISTEN",
                            2: "TCPS_SYN_SENT",
                            3: "TCPS_SYN_RECEIVED",
                            4: "TCPS_ESTABLISHED",
                            5: "TCPS_CLOSE_WAIT",
                            6: "TCPS_FIN_WAIT_1",
                            7: "TCPS_CLOSING",
                            8: "TCPS_LAST_ACK",
                            9: "TCPS_FIN_WAIT_2",
                            10: "TCPS_TIME_WAIT",
                            },
                        target="int",
                        )]],
            }],
    "protosw": [None, {
            "pr_protocol": [None, ["Enumeration", dict(
                        # xnu-2422.1.72/bsd/netinet/in.h: 99
                        choices={
                            0: "IPPROTO_IP",
                            1: "IPPROTO_ICMP",
                            2: "IPPROTO_IGMP",
                            4: "IPPROTO_IPV4",
                            6: "IPPROTO_TCP",
                            17: "IPPROTO_UDP",
                            41: "IPPROTO_IPV6",
                            50: "IPPROTO_ESP",
                            51: "IPPROTO_AH",
                            58: "IPPROTO_ICMPV6",
                            255: "IPPROTO_RAW",
                            },
                        target="int",
                        )]],
            }],

    "OSDictionary": [None, {
            "dictionary": [None, ["Pointer", dict(
                        target="Array",
                        target_args=dict(
                            target="dictEntry",
                            count=lambda x: x.count,
                            )
                        )]],
            }],

    "OSString": [None, {
            "value": lambda x: x.obj_profile.UnicodeString(
                offset=x.string, length=x.length),
            }],

    "OSOrderedSet": [None, {
            "array": [None, ["Pointer", dict(
                        target="Array",
                        target_args=dict(
                            target="_Element",
                            count=lambda x: x.count
                            )
                        )]],
            }],

    "PE_state": [None, {
            "bootArgs": [None, ["Pointer", dict(target="boot_args")]],
            }],

    "EfiMemoryRange": [None, {
            # xnu-1699.26.8/pexpert/pexpert/i386/boot.h: 46
            "Type": [None, ["Enumeration", dict(
                        choices={
                            0: "kEfiReservedMemoryType",
                            1: "kEfiLoaderCode",
                            2: "kEfiLoaderData",
                            3: "kEfiBootServicesCode",
                            4: "kEfiBootServicesData",
                            5: "kEfiRuntimeServicesCode",
                            6: "kEfiRuntimeServicesData",
                            7: "kEfiConventionalMemory",
                            8: "kEfiUnusableMemory",
                            9: "kEfiACPIReclaimMemory",
                            10: "kEfiACPIMemoryNVS",
                            11: "kEfiMemoryMappedIO",
                            12: "kEfiMemoryMappedIOPortSpace",
                            13: "kEfiPalCode",
                            14: "kEfiMaxMemoryType",
                            },
                        target="unsigned int"
                        )]],
            }]
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
            type_name=type, offset=self.obj_offset - offset,
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
        # We sort here to ensure we have stable ordering as the output of this
        # call.
        result = sorted(self.find_all_lists(type, member),
                        key=lambda x: x.obj_offset)

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


class socket(obj.Struct):
    # /xnu-2422.1.72/bsd/kern/socket_info.c: fill_socketinfo()
    def fill_socketinfo(self):
        """Returns a dict instead of a proper socket_info struct."""
        result = utils.AttributeDict(
            domain=self.so_proto.pr_domain.dom_family,
            type=self.so_proto.pr_type,
            protocol=self.so_proto.pr_protocol,
            )

        if result.domain == "AF_INET":
            inp = self.so_pcb.dereference_as("inpcb")
            result.state = inp.inp_ppcb.dereference_as("tcpcb").t_state

            result.remote_port = utils.ntoh(inp.inp_fport)
            result.remote_ip = utils.FormatIPAddress(
                result.domain,
                inp.inp_dependfaddr.inp46_foreign.ia46_addr4.s_addr)

            result.local_port = utils.ntoh(inp.inp_lport)
            result.local_ip = utils.FormatIPAddress(
                result.domain,
                inp.inp_dependladdr.inp46_local.ia46_addr4.s_addr)

        elif result.domain == "AF_INET6":
            inp = self.so_pcb.dereference_as("inpcb")
            result.state = inp.inp_ppcb.dereference_as("tcpcb").t_state

            result.remote_port = utils.ntoh(inp.inp_fport)
            result.remote_ip = utils.FormatIPAddress(
                result.domain,
                inp.inp_dependfaddr.inp6_foreign.m("__u6_addr"))

            result.local_port = utils.ntoh(inp.inp_lport)
            result.local_ip = utils.FormatIPAddress(
                result.domain,
                inp.inp_dependladdr.inp6_local.m("__u6_addr"))

        return result


class sockaddr(obj.Struct):
    def _get_address_obj(self):
        addr = obj.NoneObject("Unknown socket family")

        if self.sa_family == "AF_INET":
            addr = self.cast("sockaddr_in").sin_addr.s_addr

        elif self.sa_family == "AF_INET6":
            addr = self.cast("sockaddr_in6").sin6_addr.m("__u6_addr")

        elif self.sa_family == "AF_LINK":
            addr = self.cast("sockaddr_dl")

        return addr

    def __str__(self):
        result = ""
        addr = self._get_address_obj()
        if addr:
            if self.sa_family in ("AF_INET6", "AF_INET"):
                result = utils.FormatIPAddress(self.sa_family, addr)

            elif self.sa_family == "AF_LINK":
                result = addr

        return str(result)


class vm_map_entry(obj.Struct):
    def find_vnode_object(self):
        """Find the underlying vnode object for the given vm_map_entry.

        xnu-2422.1.72/osfmk/vm/bsd_vm.c: 1339.
        """
        if not self.is_sub_map.v():
            #/*
            #* The last object in the shadow chain has the
            #* relevant pager information.
            #*/

            top_object = self.object.vm_object

            if top_object:
                object = top_object
                while object.shadow:
                    object = object.shadow

                if (object and not object.internal.v() and
                    object.pager_ready.v() and
                    not object.terminating.v() and
                    object.alive.v()):
                    memory_object = object.pager
                    pager_ops = memory_object.mo_pager_ops

                    # If this object points to the vnode_pager_ops, then we
                    # found what we're looking for.  Otherwise, this
                    # vm_map_entry doesn't have an underlying vnode and so we
                    # fall through to the bottom and return NULL.

                    if pager_ops == self.obj_profile.get_constant(
                        "_vnode_pager_ops"):
                        return object.pager.dereference_as(
                            "vnode_pager").vnode_handle

        return obj.NoneObject("VNode not found")


class proc(obj.Struct):
    def get_process_address_space(self):
        cr3 = self.task.map.pmap.pm_cr3
        as_class = self.obj_vm.__class__
        if self.task.map.pmap.pm_task_map == "TASK_MAP_64BIT_SHARED":
            as_class = amd64.AMD64PagedMemory

        return as_class(base=self.obj_vm.base, session=self.obj_vm.session,
                        dtb=cr3, name="Pid %s" % self.p_pid)

    @property
    def argv(self):
        result = []
        array = self.obj_profile.ListArray(
            target="String",
            offset=self.user_stack-self.p_argslen,
            vm=self.get_process_address_space(),
            maximum_size=self.p_argslen,
            )

        for item in array:
            item = unicode(item)

            # The argv array may have null padding for alignment. Discard these
            # empty strings.
            if not len(item):
                continue

            # Total size of the argv array is specified in argc (not counting
            # padding).
            if len(result) > self.p_argc:
                break

            result.append(item)

        # argv[0] is often repeated as the executable name, to avoid confusion,
        # we just discard it.
        if len(result) > 1 and result[0] == result[1]:
            result.pop(0)

        return result


class vnode(obj.Struct):
    @property
    def full_path(self):
        result = []
        vnode = self

        # Iterate here until we hit the root of the filesystem.
        while not vnode.v_flag.VROOT or not vnode.v_mount.mnt_flag.MNT_ROOTFS:
            result.append(vnode.v_name.deref())

            # If there is no parent skip to the mount point.
            vnode = vnode.v_parent or vnode.v_mount.mnt_vnodecovered

        return "/" + "/".join((unicode(x) for x in reversed(result) if x))


class OSDictionary(obj.Struct):
    """The OSDictionary is a general purpose associative array described:

    xnu-1699.26.8/libkern/libkern/c++/OSDictionary.h
    """
    def items(self, value_class=None):
        """Iterate over the associative array and yield key, value pairs."""
        for entry in self.dictionary:
            key = entry.key.dereference_as("OSString").value
            if value_class:
                yield key, entry.value.dereference_as(value_class)
            else:
                yield key, entry.value


class OSOrderedSet(obj.Struct):
    """An OSOrderedSet is a list of OSObject instances.

    xnu-1699.26.8/libkern/libkern/c++/OSOrderedSet.h
    """
    def list_of_type(self, type_name):
        for item in self.array:
            yield item.obj.dereference_as(type_name)


class Darwin32(basic.Profile32Bits, basic.BasicClasses):
    """A Darwin profile."""
    METADATA = dict(
        os="darwin",
        arch="I386",
        type="Kernel")

    @classmethod
    def Initialize(cls, profile):
        super(Darwin32, cls).Initialize(profile)
        profile.add_classes(
            LIST_ENTRY=LIST_ENTRY, queue_entry=queue_entry,
            sockaddr=sockaddr, sockaddr_dl=sockaddr_dl,
            vm_map_entry=vm_map_entry, proc=proc, vnode=vnode,
            socket=socket, OSDictionary=OSDictionary,
            OSOrderedSet=OSOrderedSet,
            )
        profile.add_overlay(darwin_overlay)
        profile.add_constants(default_text_encoding="utf8")

    def get_constant_cpp_object(self, constant, **kwargs):
        """A variant of get_constant_object which accounts for name mangling."""
        for key in self.constants:
            if constant in key:
                return self.get_constant_object(key, **kwargs)


class Darwin64(basic.ProfileLP64, Darwin32):
    """Support for 64 bit darwin systems."""
    METADATA = dict(
        os="darwin",
        arch="AMD64",
        type="Kernel")

    @classmethod
    def Initialize(cls, profile):
        super(Darwin64, cls).Initialize(profile)
        profile.add_types(darwin64_types)

    def get_constant(self, name, is_address=True):
        """Gets the constant from the profile, correcting for KASLR."""
        base_constant = super(Darwin64, self).get_constant(name)
        if is_address and isinstance(base_constant, (int, long)):
            return base_constant + self.session.GetParameter(
                "vm_kernel_slide", 0)

        return base_constant
