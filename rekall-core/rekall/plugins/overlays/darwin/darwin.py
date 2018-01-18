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

from builtins import str
from builtins import range
__author__ = "Michael Cohen <scudette@gmail.com>"

from rekall import obj

from rekall.plugins.addrspaces import amd64
from rekall.plugins.overlays import basic
from rekall_lib import utils


darwin_overlay = {
    "proc": [None, {
        # Some standard fields for Darwin processes.
        "name": lambda x: x.p_comm,
        "pid": lambda x: x.p_pid.v(),
        "dtb": lambda x: x.task.map.pmap.pm_cr3.v(),

        "p_list": [None, ["LIST_ENTRY"]],
        "p_sibling": [None, ["LIST_ENTRY"]],

        "p_comm": [None, ["UnicodeString", dict(length=17)]],
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

        "name": lambda x: x.rt_ifp.name,

        "sent": lambda x: x.m("rt_stats").nstat_txpackets,

        "rx": lambda x: x.rt_expire if x.m("rt_stats") else None,

        "delta": lambda x: (x.rt_expire - x.base_uptime
                            if x.rt_expire else 0),

    }],

    "kmod_info": [None, {
        "name": lambda x: utils.SmartUnicode(x.m("name").cast("UnicodeString")),
        "base": lambda x: x.address.v(),
        "end": lambda x: x.base + x.size,
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
                "CTLFLAG_RD": 0x80000000,  # Allow reads of variable */
                "CTLFLAG_WR": 0x40000000,  # Allow writes to the variable
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
                "VM_PROT_READ": 1,
                "VM_PROT_WRITE": 2,
                "VM_PROT_EXECUTE": 4,
            },
            target="BitField",
            target_args=dict(
                start_bit=7,
                end_bit=10
            )
        )]],
        "max_protection": [None, ["Flags", dict(
            maskmap={
                "VM_PROT_READ": 1,
                "VM_PROT_WRITE": 2,
                "VM_PROT_EXECUTE": 4,
            },
            target="BitField",
            target_args=dict(
                start_bit=10,
                end_bit=13
            )
        )]],
    }],

    "vnode": [None, {
        "v_name": [None, ["Pointer", dict(target="String")]],

        "path": lambda self: "/".join(reversed(
            [str(y.v_name.deref()) for y in self.walk_list("v_parent")])),

        # xnu-2422.1.72/bsd/sys/vnode_internal.h:230
        "v_flag": [None, ["Flags", dict(
            maskmap={
                "VROOT": 0x000001,
                "VTEXT": 0x000002,
                "VSYSTEM": 0x000004,
                "VISTTY": 0x000008,
                "VRAGE": 0x000010,
            }
        )]],
    }],

    "cat_attr": [None, {
        "ca_atime": [None, ["UnixTimeStamp"]],
        "ca_atimeondisk": [None, ["UnixTimeStamp"]],
        "ca_mtime": [None, ["UnixTimeStamp"]],
        "ca_ctime": [None, ["UnixTimeStamp"]],
        "ca_itime": [None, ["UnixTimeStamp"]],
        "ca_btime": [None, ["UnixTimeStamp"]],
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
"""))))]],

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

    "boot_args": [None, {
        "CommandLine": [None, ["String"]]
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
    indicate this inner struct is of any particular type (since its annonymous).

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

        flink = self._GetNextEntry(type, member)
        flink.find_all_lists(type, member, seen=seen)

        blink = self._GetPreviousEntry()
        blink.find_all_lists(type, member, seen=seen)

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

    def __bool__(self):
        # List entries are valid when both Flinks and Blink are valid
        return bool(self.m(self._forward)) or bool(self.m(self._backward))

    def __iter__(self):
        return self.list_of_type(self.obj_parent.obj_type, self.obj_name)


class llinfo_arp(obj.Struct):
    @utils.safe_property
    def isvalid(self):
        try:
            return self.la_rt.rt_llinfo.v() == self.obj_offset
        except AttributeError:
            return False


class queue_entry(basic.ListMixIn, obj.Struct):
    """A queue_entry is an externalized linked list.

    Although the queue_entry is defined as:

    struct queue_entry {
        struct queue_entry      *next;          /* next element */
        struct queue_entry      *prev;          /* previous element */
    };

    This is in fact not correct since the next, and prev pointers
    point to the start of the next struct. A queue_entry has a queue
    head which is also a queue entry and this can eb iterated over
    using the list_of_type method.

    NOTE: list_of_type should only be called on the head queue_entry.
    """
    _forward = "next"
    _backward = "prev"

    def list_of_type(self, type, member):
        seen = set()
        seen.add(self.prev.v())

        item = self.next.dereference_as(type)
        while item != None:
            yield item
            if item.obj_offset in seen:
                return
            seen.add(item.obj_offset)
            item = item.m(member).next.dereference_as(type)


class sockaddr_dl(obj.Struct):
    def __str__(self):
        result = []
        for i in range(self.sdl_alen):
            result.append(
                u"%.02X" % ord(self.sdl_data[self.sdl_nlen + i].v()))

        return u":".join(result)


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
        "-": "INVALID",
    }

    @utils.safe_property
    def fg_type(self):
        """Returns type of the fileglob (e.g. vnode, socket, etc.)"""
        return self.multi_m(
            # OS X 10.8 and earlier
            "f_fglob.fg_type",

            # OS X 10.9 and later
            "f_fglob.fg_ops.fo_type")

    @property
    def socket(self):
        """Return the associated socket if the dtype is for socket."""
        if self.fg_type == "DTYPE_SOCKET":
            return self.f_fglob.fg_data.dereference_as("socket")

    @property
    def vnode(self):
        """Return the associated vnode if the dtype is for vnode."""
        if self.fg_type == "DTYPE_VNODE":
            return self.f_fglob.fg_data.dereference_as("vnode")

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

    @utils.safe_property
    def human_name(self):
        return getattr(self.autocast_fg_data(), "human_name", None)

    @utils.safe_property
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
        type_name = self.so_proto.pr_type
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

            if (type_name == "SOCK_STREAM"
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

    @utils.safe_property
    def src_addr(self):
        """For IPv[46] sockets, return source IP as string."""
        return self.get_socketinfo_attr("insi_laddr")

    @utils.safe_property
    def dst_addr(self):
        """For IPv[46] sockets, return destination IP as string."""
        return self.get_socketinfo_attr("insi_faddr")

    @utils.safe_property
    def addressing_family(self):
        """The Addressing Family corresponds roughly to OSI layer 3."""
        return self.so_proto.pr_domain.dom_family

    @utils.safe_property
    def tcp_state(self):
        return self.get_socketinfo_attr("tcpsi_state")

    @utils.safe_property
    def vnode(self):
        """For Unix sockets, pointer to vnode, if any.

        This is the same way that OS gathers this information in response to
        syscall [1] (this is the API used by netstat, among others).

        1:
        https://github.com/opensource-apple/xnu/blob/10.9/bsd/kern/uipc_usrreq.c#L1683
        """
        if self.addressing_family == "AF_UNIX":
            return self.so_pcb.dereference_as("unpcb").unp_vnode

    @utils.safe_property
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

    @utils.safe_property
    def src_port(self):
        return self.get_socketinfo_attr("insi_lport")

    @utils.safe_property
    def dst_port(self):
        return self.get_socketinfo_attr("insi_fport")

    @utils.safe_property
    def l4_protocol(self):
        if self.addressing_family in ["AF_INET", "AF_INET6"]:
            # All the values start with IPPROTO_.
            return str(self.so_proto.pr_protocol).replace("IPPROTO_", "")

    @utils.safe_property
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

    @utils.safe_property
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

    @utils.safe_property
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

    @utils.safe_property
    def address(self):
        result = ""
        addr = self._get_address_obj()
        if addr:
            if self.sa_family in (u"AF_INET6", u"AF_INET"):
                result = utils.FormatIPAddress(self.sa_family, addr)

            elif self.sa_family == u"AF_LINK":
                result = addr

        return utils.SmartUnicode(result)

    def __str__(self):
        return self.address


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

            shadow = self.last_shadow
            if not shadow:
                return shadow

            if (shadow and not shadow.internal.v() and
                    shadow.pager_ready.v() and
                    not shadow.terminating.v() and
                    shadow.alive.v()):
                memory_object = shadow.pager
                pager_ops = memory_object.mo_pager_ops

                # If this object points to the vnode_pager_ops, then we
                # found what we're looking for.  Otherwise, this
                # vm_map_entry doesn't have an underlying vnode and so we
                # fall through to the bottom and return NULL.

                if pager_ops == self.obj_profile.get_constant(
                        "_vnode_pager_ops", is_address=True):
                    return shadow.pager.dereference_as(
                        "vnode_pager").vnode_handle

        return obj.NoneObject("vnode not found")

    @utils.safe_property
    def sharing_mode(self):
        """Returns the sharing mode of the backing vm_object.

        This is losely adapted from vm_map.c, void vm_map_region_top_walk(),
        except we're not filling page counts for resident/reusable, etc.
        """
        if not self.vmo_object or self.is_sub_map:
            return "SM_EMPTY"  # Nada.

        vmobj = self.vmo_object
        ref_count = vmobj.ref_count
        if vmobj.paging_in_progress:
            ref_count -= 1

        if vmobj.shadow:
            return "SM_COW"  # Copy on write.

        if self.superpage_size:
            return "SM_LARGE_PAGE"  # Shared large (huge) page.

        if self.needs_copy:
            return "SM_COW"

        if ref_count == 1 or (not vmobj.pager_trusted and not
                              vmobj.internal):
            return "SM_PRIVATE"

        return "SM_SHARED"

    @utils.safe_property
    def code_signed(self):
        return self.last_shadow.code_signed

    @utils.safe_property
    def last_shadow(self):
        shadow = self.vmo_object
        if not shadow:
            return obj.NoneObject("no vm_object found")

        while shadow.shadow:
            shadow = shadow.shadow

        return shadow

    @utils.safe_property
    def start(self):
        return self.links.start.v()

    @utils.safe_property
    def end(self):
        return self.links.end.v()

    @utils.safe_property
    def vmo_object(self):
        """Return the vm_object instance for this entry.

        There's an intermediate link called struct vm_map_entry.

        The members will be called either 'object' and 'vm_object' or
        'vme_object' and 'vmo_object'.

        There is no easy heuristic for which it will be in a particular kernel
        version* so we just try both, since they mean the same thing.

        * The kernel version numbers could be identical for kernels built from
        a feature branch and a kernel build from trunk, and the two could be
        months apart. Furthermore, the profiles are generated not from the
        kernel itself but from a debug kit and can end up using out of date
        naming conventions.
        """
        vme_object = self.multi_m("vme_object", "object")
        return vme_object.multi_m("vmo_object", "vm_object")


class clist(obj.Struct):

    @utils.safe_property
    def recovered_contents(self):
        """Gets the full contents of the ring buffer, which may be freed.

        This is different from getting the legal contents as with b_to_q [1]
        because clists are only used by TTYs and they seem to always be all
        marked as consumed, so b_to_q wouldn't let us see any content.

        1: github.com/opensource-apple/xnu/blob/10.9/bsd/kern/tty_subr.c#L358
        """
        return utils.HexDumpedString(
            self.obj_vm.read(self.c_cs, self.c_cn))

    @utils.safe_property
    def size(self):
        return int(self.c_cn)


class tty(obj.Struct):
    @utils.safe_property
    def vnode(self):
        return self.t_session.s_ttyvp

    @utils.safe_property
    def input_buffer(self):
        return self.t_rawq

    @utils.safe_property
    def output_buffer(self):
        return self.t_outq


class proc(obj.Struct):
    """Represents a Darwin process."""

    @utils.safe_property
    def address_mode(self):
        if not self.is_64bit:
            return "I386"

        return self.obj_session.profile.metadata("arch")

    @utils.safe_property
    def vads(self):
        return self.task.map.hdr.walk_list("links.next", include_current=False)

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
        ofiles = self.p_fd.fd_ofiles.deref()
        ofileflags = self.p_fd.fd_ofileflags

        if last_fd != None:
            for fd in range(last_fd + 1):  # xrange stops at N-1.
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

    @utils.safe_property
    def command(self):
        return utils.SmartUnicode(self.p_comm)

    @utils.safe_property
    def cr3(self):
        return self.task.map.pmap.pm_cr3

    @utils.safe_property
    def is_64bit(self):
        return self.task.map.pmap.pm_task_map == "TASK_MAP_64BIT"

    @utils.safe_property
    def argv(self):
        result = []
        array = self.obj_profile.ListArray(
            target="String",
            offset=self.user_stack - self.p_argslen,
            vm=self.get_process_address_space(),
            maximum_size=self.p_argslen,
        )

        for item in array:
            # Total size of the argv array is specified in argc (not counting
            # padding).
            if len(result) >= self.p_argc:
                break

            item = str(item)

            # The argv array may have null padding for alignment. Discard these
            # empty strings.
            if not len(item):
                continue

            result.append(item)

        # argv[0] is often repeated as the executable name, to avoid confusion,
        # we just discard it.
        if len(result) > 1 and result[0] == result[1]:
            result.pop(0)

        return result

    def validate(self):
        """Use heuristics to guess whether this proc is valid."""
        return (self.p_argc > 0
                and len(self.p_comm) > 0
                and self.p_start.v() > 0
                and 99999 > self.pid > 0)


class vnode(obj.Struct):
    @utils.safe_property
    def full_path(self):
        # TODO: Speed this up by caching the paths in the session.
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
                self.obj_session.logging.warning("vnode at 0x%x is orphaned.",
                                                 int(_vnode))
                return "<Orphan>"

        path = "/" + "/".join((utils.SmartUnicode(x) for x in reversed(result) if x))
        return path

    @utils.safe_property
    def human_type(self):
        return "Reg. File"

    @utils.safe_property
    def human_name(self):
        return self.full_path

    @utils.safe_property
    def cnode(self):
        """If this is an HFS vnode, then v_data is a cnode."""
        node = self.v_data.dereference_as("cnode")
        if node.c_rwlock != node:
            return obj.NoneObject("This vnode has no valid cnode.")

        return node

    @utils.safe_property
    def uid(self):
        uid = self.v_cred.cr_posix.cr_ruid
        if uid:
            return uid

        return obj.NoneObject("Could not retrieve POSIX creds.")


class cnode(obj.Struct):
    @utils.safe_property
    def created_at(self):
        return self.c_cattr.ca_ctime.as_datetime()

    @utils.safe_property
    def modified_at(self):
        return self.c_cattr.ca_mtime.as_datetime()

    @utils.safe_property
    def accessed_at(self):
        return self.c_cattr.ca_atime.as_datetime()

    @utils.safe_property
    def backedup_at(self):
        return self.c_cattr.ca_btime.as_datetime()


class zone(obj.Struct):
    @utils.safe_property
    def name(self):
        return utils.SmartUnicode(self.zone_name.deref())

    @utils.safe_property
    def count_active(self):
        return int(self.count)

    @utils.safe_property
    def count_free(self):
        return int(self.m("sum_count") - self.count)

    @utils.safe_property
    def tracks_pages(self):
        return bool(self.m("use_page_list"))

    @utils.safe_property
    def known_offsets(self):
        """Find valid offsets in the zone as tuples of (state, offset).

        Allocation zones keep track of potential places where an element of
        fixed size may be stored. The most basic zones only keep track of free
        pointers, so as to speed up allocation. Some zones also track already
        allocated data, using a separate mechanism. We support both.

        Returns a set of tuples of:
            - State, which can be "freed", "allocated" or "unknown".
            - Object offset, at which a struct may be located.
              (You will want to validate the struct itself for sanity.)
        """
        # Tracks what offsets we've looked at.
        seen_offsets = set()

        # Tracks pages we've tried to iterate through for possible offsets.
        seen_pages = set()

        # Let's walk the freed elements first. It's just a linked list:
        for element in self.free_elements.walk_list("next"):
            seen_offsets.add(element.obj_offset)

        # If we found just one known offset in a given page we actually know
        # that the whole page is dedicated to the zone allocator and other
        # offsets in it are also likely to be valid elements. Here we try to
        # discover such elements.
        for offset in seen_offsets.copy():
            # We assume pages are 4K. The zone allocator presently doesn't use
            # 2MB pages, as far as I know.
            page_start = offset & ~0xfff
            if page_start in seen_pages:
                continue

            seen_pages.add(page_start)
            seen_offsets.update(set(self._generate_page_offsets(page_start)))

        # Lastly, if we happen to track pages after they've been filled up
        # then we can go look at those pages. The relevant flag is
        # use_page_list.
        page_lists = {"all_free", "all_used", "intermediate"}

        # Field not present on OSX 10.7
        if self.m("use_page_list"):
            for page_list in page_lists:
                for page_start in self.m(page_list).walk_list("next"):
                    if page_start in seen_pages:
                        continue

                    seen_pages.add(page_start)
                    seen_offsets.update(self._generate_page_offsets(page_start))

        return seen_offsets

    def _generate_page_offsets(self, page_start):
        limit = page_start + 0x1000 - self.elem_size
        # Page metadata is always inlined at the end of the page. So that's
        # space that contain valid elements.
        if self.obj_profile.get_obj_size("zone_page_metadata"):
            limit -= self.obj_profile.get_obj_size("zone_page_metadata")

        return range(page_start, limit, self.elem_size)


class ifnet(obj.Struct):
    @utils.safe_property
    def name(self):
        return "%s%d" % (self.if_name.deref(), self.if_unit)

    @utils.safe_property
    def addresses(self):
        # There should be exactly one link layer address.
        for tqe in self.if_addrhead.tqh_first.walk_list(
                "ifa_link.tqe_next"):
            family = tqe.ifa_addr.sa_family

            # Found the L2 address (MAC)
            if family == "AF_LINK":
                l2_addr = utils.SmartUnicode(tqe.ifa_addr.deref())
                yield ("MAC", l2_addr)
                continue
            elif family == "AF_INET":
                l3_proto = "IPv4"
            elif family == "AF_INET6":
                l3_proto = "IPv6"
            else:
                l3_proto = utils.SmartUnicode(family).replace("AF_", "")

            l3_addr = utils.SmartUnicode(tqe.ifa_addr.deref())
            yield (l3_proto, l3_addr)

    @utils.safe_property
    def l2_addr(self):
        for proto, addr in self.addresses:
            if proto == "MAC":
                return addr

    @utils.safe_property
    def l3_addrs(self):
        return [(proto, addr) for proto, addr in self.addresses
                if proto != "MAC"]

    @utils.safe_property
    def ipv4_addr(self):
        result = []
        for proto, addr in self.addresses:
            if proto == "IPv4":
                result.append(addr)

        return ", ".join(result)

    @utils.safe_property
    def ipv6_addr(self):
        result = []
        for proto, addr in self.addresses:
            if proto == "IPv6":
                result.append(addr)

        return ", ".join(result)


class session(obj.Struct):
    @utils.safe_property
    def tty(self):
        return self.s_ttyp

    @utils.safe_property
    def name(self):
        return "Session %d (%s)" % (self.s_sid, self.s_leader.command)

    @utils.safe_property
    def username(self):
        return utils.SmartUnicode(self.s_login)

    @utils.safe_property
    def uid(self):
        return self.tty.vnode.uid


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
        for k in list(profile.vtypes.keys()):
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
            socket=socket, clist=clist, zone=zone, ifnet=ifnet, tty=tty,
            # Support both forms with and without _class suffix.
            OSDictionary=OSDictionary, OSDictionary_class=OSDictionary,
            OSOrderedSet=OSOrderedSet, OSOrderedSet_class=OSOrderedSet,
            fileproc=fileproc, session=session, cnode=cnode,
            llinfo_arp=llinfo_arp)
        profile.add_enums(**darwin_enums)
        profile.add_overlay(darwin_overlay)
        profile.add_constants(dict(default_text_encoding="utf8"))

    def get_constant_cpp_object(self, constant, **kwargs):
        """A variant of get_constant_object which accounts for name mangling."""
        for key in self.constants:
            if constant in key:
                return self.get_constant_object(key, **kwargs)


class Darwin64(basic.RelativeOffsetMixin, basic.ProfileLP64, Darwin32):
    """Support for 64 bit darwin systems."""
    METADATA = dict(
        os="darwin",
        arch="AMD64",
        type="Kernel")

    image_base = 0

    @classmethod
    def Initialize(cls, profile):
        super(Darwin64, cls).Initialize(profile)
        profile.add_types(darwin64_types)

    def GetImageBase(self):
        if not self.image_base:
            self.image_base = self.session.GetParameter(
                "vm_kernel_slide", 0)

        return self.image_base
