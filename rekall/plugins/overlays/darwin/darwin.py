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

import logging

from rekall import obj
from rekall import utils

from rekall.plugins.addrspaces import amd64
from rekall.plugins.overlays import basic

from rekall.plugins.collectors.darwin import darwin
from rekall.plugins.collectors.darwin import networking

darwin_overlay = {
    "proc": [None, {
        # Some standard fields for Darwin processes.
        "name": lambda x: x.p_comm,
        "pid": lambda x: x.p_pid,

        "p_list": [None, ["LIST_ENTRY"]],
        "p_sibling": [None, ["LIST_ENTRY"]],

        "p_comm": [None, ["String", dict(length=17)]],
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
        # github.com/opensource-apple/xnu/blob/10.9/bsd/sys/socket.h#L370
        "sa_family": [None, ["Enumeration", dict(
            enum_name="sa_family_t",
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
                # A node will handle locking by itself.
                "CTLFLAG_LOCKED": 0x00800000,
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
            [unicode(y.v_name.deref()) for y in self.walk_list("v_parent")])),

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
        # Defined here:
        # https://github.com/opensource-apple/xnu/blob/10.9/bsd/sys/filedesc.h#L113
        "fd_ofileflags": [None, ["Pointer", dict(
            target="Array",
            target_args=dict(
                target="Flags",
                target_args=dict(
                    target="unsigned char",
                    maskmap=utils.MaskMapFromDefines("""
/*
 * Per-process open flags.
 */
#define UF_EXCLOSE      0x01            /* auto-close on exec */
#define UF_FORKCLOSE    0x02            /* auto-close on fork */
#define UF_RESERVED     0x04            /* open pending / in progress */
#define UF_CLOSING      0x08            /* close in progress */

#define UF_RESVWAIT     0x10            /* close in progress */
#define UF_INHERIT      0x20            /* "inherit-on-exec" */
"""
    ))))]],

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
        # sun_len is the number of bytes from start of the struct to the NULL
        # terminator in the sun_path member. (Yes, really. [1]) The
        # original/Volatility code used it as length of the string itself,
        # leading to a subtle bug, when the sun_path wasn't NULL-terminated
        # (which it doesn't have to be.)
        # [1]
        # https://github.com/opensource-apple/xnu/blob/10.9/bsd/sys/un.h#L77
        "sun_path": [None, ["String", dict(
            length=lambda x: (
                x.sun_len
                - x.obj_profile.get_obj_offset("sockaddr_un", "sun_path")
            ),
        )]],
    }],

    "domain": [None, {
        # xnu-2422.1.72/bsd/sys/domain.h: 99
        "dom_family": [None, ["Enumeration", dict(
            enum_name="sa_family_t",
            target="unsigned char",
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
            target="short",
        )]],
        "pr_type": [None, ["Enumeration", dict(
            enum_name="pr_type",
            target="short",
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
            offset=x.string,
            length=x.length
        ),
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

    "_Element": [8, {
        "obj": [0, ["pointer", ["OSMetaClassBase"]]]
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


darwin_enums = {
    # Socket address families, defined here because we use them in a couple of
    # places. This is a "fake enum" in the sense that the values are declared
    # as #defines, but only ever used in conjunction with a specific datatype
    # (which is sa_family_t).
    #
    # From the horse's mouth:
    # https://github.com/opensource-apple/xnu/blob/10.9/bsd/sys/socket.h#L370
    #
    # The data type is defined here:
    # https://github.com/opensource-apple/xnu/blob/10.9/bsd/sys/_types/_sa_family_t.h?source=cc#L30
    #
    # Basically the exact same fake enumeration is used in the same file for
    # protocol families here:
    # https://github.com/opensource-apple/xnu/blob/10.9/bsd/sys/socket.h#L493
    #
    # Because the numbers are the same (in fact, PF_ defines are mapped 1:1
    # with addressing families) we just use AF_ for everything.
    "sa_family_t": utils.EnumerationFromDefines("""
/*
 * Address families.
 */
#define AF_UNSPEC       0               /* unspecified */
#define AF_UNIX         1               /* local to host (pipes) */
#define AF_INET         2               /* internetwork: UDP, TCP, etc. */
#define AF_IMPLINK      3               /* arpanet imp addresses */
#define AF_PUP          4               /* pup protocols: e.g. BSP */
#define AF_CHAOS        5               /* mit CHAOS protocols */
#define AF_NS           6               /* XEROX NS protocols */
#define AF_ISO          7               /* ISO protocols */
#define AF_ECMA         8               /* European computer manufacturers */
#define AF_DATAKIT      9               /* datakit protocols */
#define AF_CCITT        10              /* CCITT protocols, X.25 etc */
#define AF_SNA          11              /* IBM SNA */
#define AF_DECnet       12              /* DECnet */
#define AF_DLI          13              /* DEC Direct data link interface */
#define AF_LAT          14              /* LAT */
#define AF_HYLINK       15              /* NSC Hyperchannel */
#define AF_APPLETALK    16              /* Apple Talk */
#define AF_ROUTE        17              /* Internal Routing Protocol */
#define AF_LINK         18              /* Link layer interface */
#define pseudo_AF_XTP   19              /* eXpress Transfer Protocol (no AF) */
#define AF_COIP         20              /* connection-oriented IP, aka ST II */
#define AF_CNT          21              /* Computer Network Technology */
#define pseudo_AF_RTIP  22              /* Help Identify RTIP packets */
#define AF_IPX          23              /* Novell Internet Protocol */
#define AF_SIP          24              /* Simple Internet Protocol */
#define pseudo_AF_PIP   25              /* Help Identify PIP packets */
#define AF_NDRV         27              /* Network Driver 'raw' access */
#define AF_ISDN         28              /* Integrated Services Digital Network*/
#define pseudo_AF_KEY   29              /* Internal key-management function */
#define AF_INET6        30              /* IPv6 */
#define AF_NATM         31              /* native ATM access */
#define AF_SYSTEM       32              /* Kernel event messages */
#define AF_NETBIOS      33              /* NetBIOS */
#define AF_PPP          34              /* PPP communication protocol */
#define pseudo_AF_HDRCMPLT 35           /* Used by BPF to not rewrite headers
                                         * in interface output routine */
#define AF_AFP          36              /* Used by AFP */
#define AF_IEEE80211    37              /* IEEE 802.11 protocol */
#define AF_UTUN         38
#define AF_MULTIPATH    39
#define AF_MAX          40
"""),

    # Socket types, defined here:
    # https://github.com/opensource-apple/xnu/blob/10.9/bsd/sys/socket.h#L133
    "pr_type": utils.EnumerationFromDefines("""
/*
 * Types
 */
#define SOCK_STREAM     1               /* stream socket */
#define SOCK_DGRAM      2               /* datagram socket */
#define SOCK_RAW        3               /* raw-protocol interface */
#define SOCK_RDM        4               /* reliably-delivered message */
#define SOCK_SEQPACKET  5               /* sequenced packet stream */
"""),
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
    def __unicode__(self):
        result = []
        for i in xrange(self.sdl_alen):
            result.append(
                "%.02X" % ord(self.sdl_data[self.sdl_nlen + i].v()))

        return ":".join(result)


class fileproc(obj.Struct):
    """Represents an open file, owned by a process."""

    DTYPE_TO_HUMAN = {
        "DTYPE_SOCKET": "socket",
        "DTYPE_VNODE": "vnode",
        "DTYPE_PSXSEM": "POSIX Semaphore",
        "DTYPE_PSXSHM": "POSIX Shared Mem.",
        "DTYPE_KQUEUE": "kernel queue",
        "DTYPE_PIPE": "pipe",
        "DTYPE_FSEVENTS": "FS Events",  # needs more research

        # I (Adam) /believe/ this is a remnant of the AppleTalk support,
        # however nowadays it's unfortunately often used to mean basically
        # DTYPE_OTHER (which XNU doesn't have). Example of how this might be
        # used in current code:
        # opensource.apple.com/source/xnu/xnu-1456.1.26/bsd/netat/sys_dep.c
        "DTYPE_ATALK": "<unknown>",
    }

    @property
    def fg_type(self):
        """Returns type of the fileglob (e.g. vnode, socket, etc.)"""
        return (
            # OS X 10.8 and earlier
            self.f_fglob.m("fg_type") or

            # OS X 10.9 and later
            self.f_fglob.fg_ops.fo_type)

    def autocast_fg_data(self):
        """Returns the correct struct with fg_type-specific information.

        This can be one of vnode, socket, shared memory or semaphore [1].

        Of those four, we currently only get extra information for vnode and
        socket. For everything else, we return a NoneObject.

        [1]:
          https://github.com/opensource-apple/xnu/blob/10.9/bsd/sys/file_internal.h#L184
        """
        dtype = self.fg_type

        # Semaphore and shared memory are known structs, but we currently don't
        # know of anything interesting that should be extracted from them.
        if dtype == "DTYPE_SOCKET":
            return self.f_fglob.fg_data.dereference_as("socket")
        elif dtype == "DTYPE_VNODE":
            return self.f_fglob.fg_data.dereference_as("vnode")
        # elif dtype == "DTYPE_PSXSEM":
        #     return self.f_fglob.fg_data.dereference_as("semaphore")
        # elif dtype == "DTYPE_PSXSHM":
        #     return self.f_fglob.fg_data.dereference_as("vm_shared_region")

        # That would be an unknown DTYPE.
        return self.f_fglob.fg_data

    @property
    def human_name(self):
        return getattr(self.autocast_fg_data(), "human_name", None)

    @property
    def human_type(self):
        # Delegate to fg_data if it thinks it knows what it is.
        return getattr(
            self.autocast_fg_data(),
            "human_type",
            self.DTYPE_TO_HUMAN[str(self.fg_type)]
        )


class socket(obj.Struct):
    """Provides human-readable accessors for sockets of the more common AFs.

    This class has two basic ways of getting information. Most attributes are
    computed using the method fill_socketinfo, which is directly adapted from
    the kernel function of the same name. For the few things that
    fill_socketinfo doesn't care about, the properties themselves get the
    data and provide references to the kernel source for anyone wondering
    why and how all this works.
    """

    cached_socketinfo = None

    def fill_socketinfo(self):
        """Computes information about sockets of some addressing families.

        This function is directly adapted from the kernel function
        fill_socketinfo [1]. The original function is used to fill a struct
        with addressing and other useful information about sockets of a few
        key addressing families. All families are supported, but only the
        following will return useful information:
          - AF_INET (IPv4)
          - AF_INET6 (IPv6)
          - AF_UNIX (Unix socket)
          - AF_NDRV (Network driver raw access)
          - AF_SYSTEM (Darwin-specific; see documentation [3])

        Differences between the kernel function and this adaptation:
          - The kernel uses Protocol Families (prefixed with PF_). Rekall
          relies on Addressing Families (AF_) which are exactly the same.

          - The kernel fills a struct; this function returns a dict with the
          same members.

          - The kernel returns the data raw. This function converts endianness
          and unions to human-readable representations, as appropriate.

          - Only a subset of members are filled in.

          - Other differences as documented in code.

        Returns:
          A dict with the same members as struct socket_info and related.
          Only member that's always filled is "soi_kind". That's not Spanish,
          but one of the values in this anonymous enum [2], which determines
          what other members are present. (Read the code.)

        [1]
        https://github.com/opensource-apple/xnu/blob/10.9/bsd/kern/socket_info.c#L98
        [2]
        https://github.com/opensource-apple/xnu/blob/10.9/bsd/sys/proc_info.h#L503
        [3] "KEXT Controls and Notifications"
        https://developer.apple.com/library/mac/documentation/Darwin/Conceptual/NKEConceptual/control/control.html
        """
        domain = self.so_proto.pr_domain.dom_family
        type = self.so_proto.pr_type
        protocol = self.so_proto.pr_protocol

        si = {"soi_kind": "SOCKINFO_GENERIC"}

        # The kind of socket is determined by the triplet
        # {domain, type, protocol}
        if domain in ["AF_INET", "AF_INET6"]:
            si["soi_kind"] = "SOCKINFO_IN"

            inp = self.so_pcb.dereference_as("inpcb")

            si["insi_fport"] = utils.ntoh(inp.inp_fport)
            si["insi_lport"] = utils.ntoh(inp.inp_lport)
            si["insi_ip_ttl"] = inp.inp_ip_ttl.v()

            # Different from kernel: insi_[df]addr is a union, and by setting
            # the IPv6 address, you set the IPv4 address too. We instead return
            # a string with the appropriately formatted address.
            if domain == "AF_INET":
                si["insi_faddr"] = utils.FormatIPAddress(
                    "AF_INET",
                    inp.inp_dependfaddr.inp46_foreign.ia46_addr4.s_addr
                )
                si["insi_laddr"] = utils.FormatIPAddress(
                    "AF_INET",
                    inp.inp_dependladdr.inp46_local.ia46_addr4.s_addr
                )
            else:
                si["insi_faddr"] = utils.FormatIPAddress(
                    "AF_INET6",
                    inp.inp_dependfaddr.inp6_foreign.m("__u6_addr")
                )
                si["insi_laddr"] = utils.FormatIPAddress(
                    "AF_INET6",
                    inp.inp_dependladdr.inp6_local.m("__u6_addr")
                )

            if (type == "SOCK_STREAM"
                and (protocol == 0 or protocol == "IPPROTO_TCP")
                and inp.inp_ppcb != None):

                tp = inp.inp_ppcb.dereference_as("tcpcb")
                si["soi_kind"] = "SOCKINFO_TCP"

                si["tcpsi_state"] = tp.t_state
                si["tcpsi_flags"] = tp.t_flags
        elif domain == "AF_UNIX":
            unp = self.so_pcb.dereference_as("unpcb")
            si["soi_kind"] = "SOCKINFO_UN"

            if unp.unp_addr:
                # Difference from kernel: instead of copying the whole unp_addr
                # struct, we just get delegate getting the actual string to the
                # unp_addr struct. (Because it's trickier than it looks.)
                si["unsi_addr"] = unp.unp_addr.sun_path

        elif domain == "AF_NDRV":
            # This is how we get the pcb if we need to:
            # ndrv_cb = self.so_pcb.dereference_as("ndrv_cb")
            si["soi_kind"] = "SOCKINFO_NDRV"
        elif domain == "AF_SYSTEM":
            # AF_SYSTEM domain needs more research. It looks like it's used to
            # communicate between user space and kernel extensions, and allows
            # the former to control the latter. Naively, this looks ripe for
            # rootkits to me.
            if protocol == "SYSPROTO_EVENT":
                # This is how we get the pcb if we need to:
                # ev_pcb = self.so_pcb.dereference_as("kern_event_pcb")
                si["soi_kind"] = "SOCKINFO_KERN_EVENT"
            elif protocol == "SYSPROTO_CONTROL":
                kcb = self.so_pcb.dereference_as("ctl_cb")
                kctl = kcb.kctl
                si["soi_kind"] = "SOCKINFO_KERN_CTL"

                if kctl:
                    si["kcsi_id"] = kctl.id
                    si["kcsi_name"] = kctl.name

        return si

    def get_socketinfo_attr(self, attr):
        """Run fill_socketinfo if needed, cache result, return value of attr."""
        if not self.cached_socketinfo:
            self.cached_socketinfo = self.fill_socketinfo()

        if attr not in self.cached_socketinfo:
            return obj.NoneObject(
                "socket of family {}/{} has no member {}".format(
                    self.addressing_family,
                    self.cached_socketinfo["soi_kind"],
                    attr))

        return self.cached_socketinfo[attr]


    @property
    def src_addr(self):
        """For IPv[46] sockets, return source IP as string."""
        return self.get_socketinfo_attr("insi_laddr")

    @property
    def dst_addr(self):
        """For IPv[46] sockets, return destination IP as string."""
        return self.get_socketinfo_attr("insi_faddr")

    @property
    def addressing_family(self):
        """The Addressing Family corresponds roughly to OSI layer 3."""
        return self.so_proto.pr_domain.dom_family

    @property
    def tcp_state(self):
        return self.get_socketinfo_attr("tcpsi_state")

    @property
    def vnode(self):
        """For Unix sockets, pointer to vnode, if any.

        This is the same way that OS gathers this information in response to
        syscall [1] (this is the API used by netstat, among others).

        1:
        https://github.com/opensource-apple/xnu/blob/10.9/bsd/kern/uipc_usrreq.c#L1683
        """
        if self.addressing_family == "AF_UNIX":
            return self.so_pcb.dereference_as("unpcb").unp_vnode

    @property
    def unp_conn(self):
        """For Unix sockets, the pcb of the paired socket. [1]

        You most likely want to do sock.conn_pcb.unp_socket to get at the
        other socket in the pair. However, because the sockets are paired
        through the protocol control block, it's actually useful to have
        a direct pointer at it in order to be able to spot paired sockets.

        1:
        https://github.com/opensource-apple/xnu/blob/10.9/bsd/sys/unpcb.h#L128
        """
        if self.addressing_family == "AF_UNIX":
            return self.so_pcb.dereference_as("unpcb").unp_conn

    @property
    def src_port(self):
        return self.get_socketinfo_attr("insi_lport")

    @property
    def dst_port(self):
        return self.get_socketinfo_attr("insi_fport")

    @property
    def l4_protocol(self):
        if self.addressing_family in ["AF_INET", "AF_INET6"]:
            # All the values start with IPPROTO_.
            return str(self.so_proto.pr_protocol).replace("IPPROTO_", "")

    @property
    def unix_type(self):
        if self.addressing_family == "AF_UNIX":
            pr_type = str(self.so_proto.pr_type)

            if pr_type:
                # All values begin with SOCK_.
                return pr_type.replace("SOCK_", "")
            else:
                # I am about 80% sure that this should never happen. Before
                # deciding how this should be handled (possibly by logging an
                # error), I'll need to do more research.
                return "Unix Socket"

    @property
    def human_name(self):
        if self.addressing_family in ["AF_INET", "AF_INET6"]:
            if self.l4_protocol in ["TCP", "UDP"]:
                return "{} ({}) -> {} ({})".format(
                    self.src_addr, self.src_port,
                    self.dst_addr, self.dst_port)

            return "{} -> {}".format(self.src_addr, self.dst_addr)

        if self.addressing_family == "AF_UNIX":
            return self.get_socketinfo_attr("unsi_addr")

        return None

    @property
    def human_type(self):
        if self.addressing_family == "AF_INET":
            return "{}v4".format(self.l4_protocol)

        if self.addressing_family == "AF_INET6":
            proto = self.l4_protocol

            # Some v6 protocols are already named with v6 in the name.
            if proto.endswith("6"):
                return proto

            return "{}v6".format(self.l4_protocol)

        if self.addressing_family == "AF_UNIX":
            return self.unix_type

        return "Sock: {}".format(self.addressing_family)


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

    def __unicode__(self):
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
    def get_open_files(self):
        """Gets all open files (sockets, pipes...) owned by this proc.

        Yields:
          tuple of (fd, fileproc, flags)
        """
        # lastfile is a high water mark of valid fds [1]. That doesn't mean
        # there are no invalid fds at lower indexes! fd_freefile is a free
        # descriptor that tends to gravitate towards the lowest index as
        # as seen here [2]. When the kernel frees an fd it sets the pointer
        # to NULL and also clears the corresponding index in fd_ofilesflags
        # [3]. This creates a sparse array, so the search has to skip over
        # invalid fds along the way, just as the kernel does [4]. We skip
        # NULL pointers (and invalid pointers) but don't check for cleared
        # flags, since they're usually zero anyway.
        #
        # [1]:
        # https://github.com/opensource-apple/xnu/blob/10.9/bsd/sys/filedesc.h#L96
        # [2]:
        # https://github.com/opensource-apple/xnu/blob/10.9/bsd/kern/kern_descrip.c#L412
        # [3]:
        # https://github.com/opensource-apple/xnu/blob/10.9/bsd/kern/kern_descrip.c#L384
        # [4]:
        # https://github.com/opensource-apple/xnu/blob/10.9/bsd/kern/kern_descrip.c#L2960
        last_fd = self.p_fd.fd_lastfile
        ofiles = self.p_fd.fd_ofiles
        ofileflags = self.p_fd.fd_ofileflags

        for fd in xrange(last_fd + 1):  # xrange stops at N-1.
            file_obj = ofiles[fd].deref()

            # file_obj will be None if the pointer is NULL (see ref [4]), and
            # also when the pointer is simply invalid, which can happen
            # sometimes. Currently, I chalk it up to inconsistencies in the
            # volatile RAM image (since it's rare) but it might have another
            # explanation.
            if file_obj:
                yield (fd, file_obj, ofileflags[fd])

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
        _vnode = self

        # Iterate here until we hit the root of the filesystem.
        while not (_vnode.v_flag.VROOT and
                   _vnode.v_mount.mnt_flag.MNT_ROOTFS):
            result.append(_vnode.v_name.deref())

            # If there is no parent skip to the mount point.
            _vnode = _vnode.v_parent or _vnode.v_mount.mnt_vnodecovered

            # This is rare, but it does happen. I currently don't understand
            # why, so we just log a warning and report the node as an orphan.
            if not _vnode:
                logging.warning("vnode at 0x%x is orphaned.", int(_vnode))
                return "<Orphan>"

        return "/" + "/".join((unicode(x) for x in reversed(result) if x))

    @property
    def human_type(self):
        return "Reg. File"

    @property
    def human_name(self):
        return self.full_path


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

        # Some Darwin profiles add a suffix to IOKIT objects. So OSDictionary
        # becomes OSDictionary_class. We automatically generate the overlays and
        # classes to account for this.
        for k in profile.vtypes.keys():
            if k.endswith("_class"):
                stripped_k = k[:-len("_class")]
                if stripped_k not in profile.vtypes:
                    profile.vtypes[stripped_k] = profile.vtypes[k]
                    if stripped_k in darwin_overlay:
                        darwin_overlay[k] = darwin_overlay[stripped_k]

        profile.add_classes(
            LIST_ENTRY=LIST_ENTRY, queue_entry=queue_entry,
            sockaddr=sockaddr, sockaddr_dl=sockaddr_dl,
            vm_map_entry=vm_map_entry, proc=proc, vnode=vnode,
            socket=socket,
            # Support both forms with and without _class suffix.
            OSDictionary=OSDictionary, OSDictionary_class=OSDictionary,
            OSOrderedSet=OSOrderedSet, OSOrderedSet_class=OSOrderedSet,
            fileproc=fileproc,
        )
        profile.add_enums(**darwin_enums)
        profile.add_overlay(darwin_overlay)
        profile.add_constants(default_text_encoding="utf8")

        profile.add_collector(
            collector=networking.NetworkInterfaces,
            components=["Named", "NetworkInterface"],
        )

        profile.add_collector(
            collector=networking.FileprocHandleCollector,
            components=["Handle", "MemoryObject", "Resource"],
        )

        profile.add_collector(
            collector=networking.HandleSocketCollector,
            components=["Connection", "Named"],
        )

        profile.add_collector(
            collector=darwin.DarwinPgrpHashProcessCollector,
            components=["Named", "Process", "User", "MemoryObject"],
        )

        profile.add_collector(
            collector=darwin.DarwinTaskProcessCollector,
            components=["Named", "Process", "User", "MemoryObject"],
        )

        profile.add_collector(
            collector=darwin.DarwinAllprocProcessCollector,
            components=["Named", "Process", "User", "MemoryObject"],
        )

        profile.add_collector(
            collector = darwin.DarwinPidHashProcessCollector,
            components=["Named", "Process", "User", "MemoryObject"],
        )

        profile.add_collector(
            collector = networking.UnixSocketCollector,
            components=["Connection", "Named"],
        )


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
