# Rekall Memory Forensics
# Copyright (C) 2010 Brendan Dolan-Gavitt
# Copyright (c) 2011 Michael Cohen <scudette@gmail.com>
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

"""
@author:       Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      brendandg@gatech.edu
@organization: Georgia Institute of Technology
"""
# pylint: disable=protected-access

from rekall import obj
from rekall import utils

from rekall.plugins.overlays import basic
from rekall.plugins.overlays.linux import vfs


linux_overlay = {
    'task_struct' : [None, {
        'state': [None, ['Flags', dict(
            maskmap=utils.MaskMapFromDefines("""
# From http://lxr.free-electrons.com/source/include/linux/sched.h#L207
#define TASK_RUNNING            0
#define TASK_INTERRUPTIBLE      1
#define TASK_UNINTERRUPTIBLE    2
#define TASK_STOPPED          4
#define TASK_TRACED           8
#define TASK_DEAD               64
#define TASK_WAKEKILL           128
#define TASK_WAKING             256
#define TASK_PARKED             512
#define TASK_STATE_MAX          1024
"""))]],
        'exit_state': [None, ['Flags', dict(
            maskmap=utils.MaskMapFromDefines("""
# From http://lxr.free-electrons.com/source/include/linux/sched.h#L207
/* in tsk->exit_state */
#define EXIT_ZOMBIE             16
#define EXIT_DEAD               32
/* in tsk->state again */
"""))]],

        # Common pseudo fields to provide cross OS compatibility.
        'name': lambda x: x.comm,
        'dtb': lambda x: x.obj_vm.vtop(x.mm.pgd.v()),

        'comm': [None, ['UnicodeString', dict(length=16)]],
        'uid': lambda x: x.m("uid") or x.cred.uid,
        'gid': lambda x: x.m("gid") or x.cred.gid,
        'euid': lambda x: x.m("euid") or x.cred.euid,
        }],

    'module' : [None, {
        'name': lambda x: utils.SmartUnicode(
            x.m("name").cast('UnicodeString', length=60)),
        'base': lambda x: x.module_core.v(),
        'size': lambda x: x.core_size,
        'end': lambda x: x.base + x.core_size,
        'kp': [None, ['Pointer', dict(
            target='Array',
            target_args=dict(
                target='kernel_param',
                count=lambda x: x.num_kp))]],
        }],

    'kernel_param': [None, {
        'name' : [None, ['Pointer', dict(target='UnicodeString')]],
        'getter_addr': lambda x: (x.m("get") or x.ops.get),
        }],

    'kparam_array': [None, {
        'getter_addr': lambda x: (x.m("get") or x.ops.get),
        }],

    'super_block' : [None, {
        's_id' : [None, ['UnicodeString', dict(length=32)]],
        'major': lambda x: x.s_dev >> 20,
        'minor': lambda x: x.s_dev & ((1 << 20) - 1),
        }],

    'net_device'  : [None, {
        'flags': [None, ['Flags', dict(
            maskmap=utils.MaskMapFromDefines("""
http://lxr.free-electrons.com/source/include/linux/if.h?v=2.6.32#L31

/* Standard interface flags (netdevice->flags). */
 30 #define IFF_UP          0x1             /* interface is up              */
 31 #define IFF_BROADCAST   0x2             /* broadcast address valid      */
 32 #define IFF_DEBUG       0x4             /* turn on debugging            */
 33 #define IFF_LOOPBACK    0x8             /* is a loopback net            */
 34 #define IFF_POINTOPOINT 0x10            /* interface is has p-p link    */
 35 #define IFF_NOTRAILERS  0x20            /* avoid use of trailers        */
 36 #define IFF_RUNNING     0x40            /* interface RFC2863 OPER_UP    */
 37 #define IFF_NOARP       0x80            /* no ARP protocol              */
 38 #define IFF_PROMISC     0x100           /* receive all packets          */
 39 #define IFF_ALLMULTI    0x200           /* receive all multicast packets*/
 40
 41 #define IFF_MASTER      0x400           /* master of a load balancer    */
 42 #define IFF_SLAVE       0x800           /* slave of a load balancer     */
 43
 44 #define IFF_MULTICAST   0x1000          /* Supports multicast           */
 45
 46 #define IFF_PORTSEL     0x2000          /* can set media type           */
 47 #define IFF_AUTOMEDIA   0x4000          /* auto media select active     */
 48 #define IFF_DYNAMIC     0x8000          /* dialup device with changing addresses*/
 49
 50 #define IFF_LOWER_UP    0x10000         /* driver signals L1 up         */
 51 #define IFF_DORMANT     0x20000         /* driver signals dormant       */
 52
 53 #define IFF_ECHO        0x40000         /* echo sent packets            */
"""))]],
        'name' : [None, ['UnicodeString', dict(length=16)]],

        'ip_ptr': [None, ['Pointer', dict(target="in_device")]],
        }],

    'in_ifaddr': [None, {
        'ifa_address': [None, ['Ipv4Address']],
        'ifa_label': [None, ['String']],
        }],

    'sockaddr_un' : [None, {
        'sun_path'      : [None, ['UnicodeString', dict(length=108)]],
        }],

    'cpuinfo_x86' : [None, {
        'x86_model_id'  : [None, ['UnicodeString', dict(length=64)]],
        'x86_vendor_id' : [None, ['UnicodeString', dict(length=16)]],
        }],

    'module_sect_attr': [None, {
        'name': [None, ['Pointer', dict(target='UnicodeString')]]
        }],

    # The size of the log record is stored in the len member.
    'log': [lambda x: x.m("len"), {
        # The log message starts after the level member.
        'message': [lambda x: x.flags.obj_offset + x.flags.obj_size,
                    ['UnicodeString', dict(
                        # The length of the message is the text and an optional
                        # dict.
                        length=lambda x: x.text_len + x.dict_len)]],

        'level': [None, ['Enumeration', {
            'choices': {
                0: 'LOG_EMERG',
                1: 'LOG_ALERT',
                2: 'LOG_CRIT',
                3: 'LOG_ERR',
                4: 'LOG_WARNING',
                5: 'LOG_NOTICE',
                6: 'LOG_INFO',
                7: 'LOG_DEBUG'
                },
            'target': 'BitField',
            'target_args': dict(
                start_bit=0, end_bit=3),
            }]],
        }],

    "file": [None, {
        "dentry": lambda x: x.m("f_dentry") or x.f_path.dentry,
        "vfsmnt": lambda x: x.m("f_vfsmnt") or x.f_path.mnt,
        }],

    'vm_area_struct' : [None, {
        'vm_flags' : [None, ['PermissionFlags', dict(
            bitmap={
                'r': 0,
                'w': 1,
                'x': 2
                }
            )]],
        }],

    'dentry': [None, {
        'd_flags': [None, ['Flags', dict(
            maskmap={
                # /* autofs: "under construction" */
                "DCACHE_AUTOFS_PENDING": 0x0001,
                #     /* this dentry has been "silly renamed" and
                #     has to be deleted on the last dput() */
                "DCACHE_NFSFS_RENAMED":  0x0002,
                "DCACHE_DISCONNECTED":  0x0004,
                #  /* Recently used, don't discard. */
                "DCACHE_REFERENCED": 0x0008,
                "DCACHE_UNHASHED": 0x0010,
                #  /* Parent inode is watched by inotify */
                "DCACHE_INOTIFY_PARENT_WATCHED": 0x0020,
                #  /* Parent inode is watched by some fsnotify
                #  listener */
                "DCACHE_FSNOTIFY_PARENT_WATCHED":  0x0080,
                },
            target="unsigned int",
            )]],
        'is_root': lambda x: x == x.d_parent,
        }],
    'd_name': [None, {
        'd_name': [None, ['Pointer', dict(
            target="String")]],
        }],

    'qstr': [None, {
        'len': lambda x: (x.m("len") or
                          x.m("u1.u1.len") or
                          # Worst case scenario, when dwarf parsing epicfailed.
                          (x.m("u1.hash_len") & 0xFFFFFFFF00000000) >> 32),
        'name': [None, ['Pointer', dict(
            target='UnicodeString',
            target_args=dict(
                # include/linux/limits.h
                length=lambda x: (min(x.len, 255)),
                )
            )]],
        }],

    "files_struct": [None, {
        # Version independent pointer to the fd table.
        '_fd': lambda x: x.m("fdt").fd or x.fd,

        # The fds table is an array of pointers to file structs. The index
        # into the array is known in user space as a file descriptor. If the
        # pointer in the array is invalid, the file descriptor is closed.
        'fds': lambda x: x._fd.dereference_as(
            "Array",
            target_args=dict(
                target="Pointer",
                target_args=dict(
                    target="file"
                    ),
                count=lambda x: x.m("fdt").max_fds or x.max_fds,
                )
            )
        }],

    "kobject": [None, {
        'name': [None, ["Pointer", dict(
            target="String",
            target_args=dict(length=32),
            )]],
        }],

    'gate_struct64': [None, {
        'address': lambda x: obj.Pointer.integer_to_address(
                              x.offset_low |
                              x.offset_middle << 16 |
                              x.offset_high << 32),
        'gate_type': [5, ['Enumeration', {
            'choices': {
                5: '32-bit Task Gate',
                6: '16-bit Int Gate',
                7: '16-bit Trap Gate',
                14: '32-bit Int Gate',
                15: '32-bit Trap Gate',
                },
            'target': 'BitField',
            'target_args': dict(
                start_bit=0, end_bit=4),
            }]],
        'present': lambda x: x.m("p"),
        }],

    'desc_struct': [None, {
        'address': lambda x: ((x.u1.u1.b & 0xffff0000) |
                              (x.u1.u1.a & 0x0000ffff)),
        'gate_type': [5, ['Enumeration', {
            'choices': {
                5: '32-bit Task Gate',
                6: '16-bit Int Gate',
                7: '16-bit Trap Gate',
                14: '32-bit Int Gate',
                15: '32-bit Trap Gate',
                },
            'target': 'BitField',
            'target_args': dict(
                start_bit=0, end_bit=4),
            }]],
        'dpl': lambda x: x.m("u1.u2.dpl"),
        'present': lambda x: x.m("u1.u2.p"),
        }],

    'tty_driver': [None, {
        "name": [None, ["Pointer", dict(
            target="String"
            )]],

        "ttys": [None, ["Pointer", dict(
            target="Array",
            target_args=dict(
                count=lambda x: x.num,
                target="Pointer",
                target_args=dict(
                    target="tty_struct"
                    )
                )
            )]],
        }],

    'tty_struct': [None, {
        'name': [None, ["String"]],
        }],

    "resource": [None, {
        "name": [None, ["Pointer", dict(
            target="String"
            )]],
        }],
    "sock": [None, {
        # http://lxr.free-electrons.com/source/include/linux/net.h#L58
        "sk_type": [None, ["Enumeration", dict(
            choices={
                1:"SOCK_STREAM",
                2:"SOCK_DGRAM",
                3:"SOCK_RAW",
                4:"SOCK_RDM",
                5:"SOCK_SEQPACKET",
                6:"SOCK_DCCP",
                10:"SOCK_PACKET",
                },
            target="BitField",
            target_args=dict(
                start_bit=16, end_bit=32))]],

        "sk_protocol": [None, ["Enumeration", dict(
            # http://lxr.free-electrons.com/source/include/uapi/linux/in.h?#L26
            choices={
                0:"IPPROTO_HOPOPT", # Dummy protocol forTCP

                # Internet Control Message Protocol
                1:"IPPROTO_ICMP",

                # Internet Group Management Protocol
                2:"IPPROTO_IGMP",

                # IPIP tunnels (older KA9Q tunnels use 94)
                4:"IPPROTO_IPV4",
                6:"IPPROTO_TCP", # Transmission Control Protocol
                8:"IPPROTO_EGP", # Exterior Gateway Protocol
                12:"IPPROTO_PUP", # PUP protocol
                17:"IPPROTO_UDP", # User Datagram Protocol
                22:"IPPROTO_IDP", # XNS IDP protocol
                29:"IPPROTO_TP", # SO Transport Protocol Class 4

                # Datagram Congestion Control Protocol
                33:"IPPROTO_DCCP",
                41:"IPPROTO_IPV6", # IPv6-in-IPv4 tunnelling
                46:"IPPROTO_RSVP", # RSVP Protocol

                # Cisco GRE tunnels (rfc 1701",1702)
                47:"IPPROTO_GRE",

                # Encapsulation Security Payload protocol
                50:"IPPROTO_ESP",
                51:"IPPROTO_AH", # Authentication Header protocol

                # Multicast Transport Protocol
                92:"IPPROTO_MTP",

                # IP option pseudo header for BEET
                94:"IPPROTO_BEETPH",
                98:"IPPROTO_ENCAP", # Encapsulation Header
                103:"IPPROTO_PIM", # Protocol Independent Multicast
                108:"IPPROTO_COMP", # Compression Header Protocol

                # Stream Control Transport Protocol
                132:"IPPROTO_SCTP",
                136:"IPPROTO_UDPLITE", # UDP-Lite (RFC 3828)
                255:"IPPROTO_RAW", # Raw IP packets
                },
            target="BitField",
            target_args=dict(
                start_bit=8, end_bit=16),
            )]],
        }],
    "sock_common": [None, {
        "skc_state": [None, ["Enumeration", dict(
            # http://lxr.free-electrons.com/source/include/net/tcp_states.h#L16
            # Because these states are not only used by AF_INET*
            # with TCP proto, we removed the TCP_ prefix to make
            # them more readable.
            choices={
                1:"ESTABLISHED",
                2:"SYN_SENT",
                3:"SYN_RECV",
                4:"FIN_WAIT1",
                5:"FIN_WAIT2",
                6:"TIME_WAIT",
                7:"CLOSE",
                8:"CLOSE_WAIT",
                9:"LAST_ACK",
                10:"LISTEN",
                11:"CLOSING",
                },
            target="unsigned char",
            )]],

        "skc_family": [None, ["Enumeration", dict(
            choices=utils.EnumerationFromDefines("""
http://lxr.free-electrons.com/source/include/linux/socket.h#L140

/* Supported address families. */
141 #define AF_UNSPEC       0
142 #define AF_UNIX         1       /* Unix domain sockets          */
143 #define AF_LOCAL        1       /* POSIX name for AF_UNIX       */
144 #define AF_INET         2       /* Internet IP Protocol         */
145 #define AF_AX25         3       /* Amateur Radio AX.25          */
146 #define AF_IPX          4       /* Novell IPX                   */
147 #define AF_APPLETALK    5       /* AppleTalk DDP                */
148 #define AF_NETROM       6       /* Amateur Radio NET/ROM        */
149 #define AF_BRIDGE       7       /* Multiprotocol bridge         */
150 #define AF_ATMPVC       8       /* ATM PVCs                     */
151 #define AF_X25          9       /* Reserved for X.25 project    */
152 #define AF_INET6        10      /* IP version 6                 */
153 #define AF_ROSE         11      /* Amateur Radio X.25 PLP       */
154 #define AF_DECnet       12      /* Reserved for DECnet project  */
155 #define AF_NETBEUI      13      /* Reserved for 802.2LLC project*/
156 #define AF_SECURITY     14      /* Security callback pseudo AF */
157 #define AF_KEY          15      /* PF_KEY key management API */
158 #define AF_NETLINK      16

160 #define AF_PACKET       17      /* Packet family                */
161 #define AF_ASH          18      /* Ash                          */
162 #define AF_ECONET       19      /* Acorn Econet                 */
163 #define AF_ATMSVC       20      /* ATM SVCs                     */
164 #define AF_RDS          21      /* RDS sockets                  */
165 #define AF_SNA          22      /* Linux SNA Project (nutters!) */
166 #define AF_IRDA         23      /* IRDA sockets                 */
167 #define AF_PPPOX        24      /* PPPoX sockets                */
168 #define AF_WANPIPE      25      /* Wanpipe API Sockets */
169 #define AF_LLC          26      /* Linux LLC                    */
170 #define AF_IB           27      /* Native InfiniBand address    */
171 #define AF_CAN          29      /* Controller Area Network      */
172 #define AF_TIPC         30      /* TIPC sockets                 */
173 #define AF_BLUETOOTH    31      /* Bluetooth sockets            */
174 #define AF_IUCV         32      /* IUCV sockets                 */
175 #define AF_RXRPC        33      /* RxRPC sockets                */
176 #define AF_ISDN         34      /* mISDN sockets                */
177 #define AF_PHONET       35      /* Phonet sockets               */
178 #define AF_IEEE802154   36      /* IEEE802154 sockets           */
179 #define AF_CAIF         37      /* CAIF sockets                 */
180 #define AF_ALG          38      /* Algorithm sockets            */
181 #define AF_NFC          39      /* NFC sockets                  */
182 #define AF_VSOCK        40      /* vSockets                     */
183 #define AF_MAX          41      /* For now.. */
"""),
            target="short unsigned int"
            )]],
    }],
    "mount": [None, {
        "mnt_devname": [None, ["Pointer", dict(target="String")]],
        "mnt_root": lambda x: x.m("mnt_root") or x.m("mnt.mnt_root"),
        }],
    "vfsmount": [None, {
        "mnt_devname": [None, ["Pointer", dict(target="String")]],
        "mnt_flags": [None, ["Flags", dict(
            maskmap={
                # include/linux/mount.h
                "nosuid": 0x01,
                "nodev": 0x02,
                "noexec": 0x04,
                "noatime": 0x08,
                "nodiratime": 0x10,
                "relatime": 0x20,
                "ro": 0x40,
                "shrinkable": 0x100,
                "writehold": 0x200,
                "shared": 0x1000,
                "unbindable": 0x2000,
                },
            target="unsigned int",
            )]],
        "mnt": lambda x: x,
    }],

    "file_system_type": [None, {
        "name": [None, ["Pointer", dict(target="String")]],
    }],

    "inode": [None, {
        "i_mode": [None, ["InodePermission", dict(
            target="unsigned int",
            )]],
        "type": lambda x: x.m("i_mode").cast(
            "Enumeration", choices={
                1: "S_IFIFO",
                2: "S_IFCHR",
                4: "S_IFDIR",
                6: "S_IFBLK",
                8: "S_IFREG",
                10: "S_IFLNK",
                12: "S_IFSOCK",
                },
            target="BitField",
            target_args=dict(start_bit=12, end_bit=16),
            ),
        "mode": lambda x: x.m("i_mode").cast(
            "Flags",
            maskmap=utils.MaskMapFromDefines("""
# From http://lxr.free-electrons.com/source/include/uapi/linux/stat.h
#define S_ISUID  0004000
#define S_ISGID  0002000
#define S_ISVTX  0001000

#define S_IRUSR 00400
#define S_IWUSR 00200
#define S_IXUSR 00100

#define S_IRGRP 00040
#define S_IWGRP 00020
#define S_IXGRP 00010

#define S_IROTH 00004
#define S_IWOTH 00002
#define S_IXOTH 00001
"""),
            target="BitField",
            target_args=dict(start_bit=0, end_bit=12),
            ),
        }],
    "radix_tree_node": [None, {
        "rcu_head": lambda x: x.m("rcu_head") or x.m("u1.rcu_head"),
        }],
    "tk_core": [None,  {
        "seq": [0, ["seqcount"]],
        "timekeeper": [8, ["timekeeper"]],
        }],
    }


class list_head(basic.ListMixIn, obj.Struct):
    """A list_head makes a doubly linked list."""
    _forward = "next"
    _backward = "prev"


class hlist_head(list_head):
    def list_of_type(self, type, member):
        return self.first.list_of_type(type, member)

class hlist_node(list_head):
    _backward = "pprev"

    def list_of_type(self, type, member):
        head = self
        node = head
        if node:
            yield basic.container_of(node, type, member)
        while node and node != head:
            yield basic.container_of(node, type, member)
            node = node.next.deref()

    def find_all_lists(self, seen):
        stack = [self]
        while stack:
            item = stack.pop()
            if item not in seen:
                seen.append(item)

                # In hlist, prev is a **
                Blink = item.m(self._backward).deref()
                if Blink.is_valid():
                    stack.append(Blink.dereference())

                Flink = item.m(self._forward)
                if Flink.is_valid():
                    stack.append(Flink.dereference())

    def __empty__(self):
        return self.m(self._forward) == self.m(self._backward).deref()


class inet_sock(obj.Struct):
    """Class for an internet socket object"""

    @utils.safe_property
    def src_port(self):
        return (self.m("sport") or self.m("inet_sport")).cast(
            "unsigned be short")

    @utils.safe_property
    def dst_port(self):
        return ((self.m("dport") or self.m("inet_dport")).cast(
            "unsigned be short") or self.sk.m("__sk_common.u3.u1.skc_dport") or
                self.sk.m("__sk_common.u3.skc_dport"))
    @utils.safe_property
    def src_addr(self):
        if self.sk.m("__sk_common").skc_family == "AF_INET":
            return (self.m("rcv_saddr") or self.m("inet_rcv_saddr") or
                    self.sk.m("__sk_common.u1.u1.skc_rcv_saddr") or
                    self.m("inet_saddr")).cast(
                        "Ipv4Address")

        else:
            return self.m("pinet6.saddr").cast("Ipv6Address")

    @utils.safe_property
    def dst_addr(self):
        if self.sk.m("__sk_common").skc_family == "AF_INET":
            return (self.m("daddr") or self.m("inet_daddr") or
                    self.sk.m("__sk_common.u1.u1.skc_daddr") or
                    self.sk.m("__sk_common.skc_daddr")).cast(
                        "Ipv4Address")

        else:
            return (self.m("pinet6.daddr").cast("Ipv6Address") or
                    self.m("pinet6.daddr_cache").cast("Ipv6Address"))


class files_struct(obj.Struct):

    def get_fds(self):
        if hasattr(self, "fdt"):
            fdt = self.fdt
            ret = fdt.fd.dereference()
        else:
            ret = self.fd.dereference()

        return ret

    def get_max_fds(self):
        if hasattr(self, "fdt"):
            ret = self.fdt.max_fds
        else:
            ret = self.max_fds

        return ret


class dentry(obj.Struct):
    @utils.safe_property
    def path(self):
        dentry_ = self

        path_components = []

        # Check for deleted dentry_.
        if self.d_flags.DCACHE_UNHASHED and not self.is_root:
            return " (deleted) "

        while len(path_components) < 50:
            if dentry_.is_root:
                break

            component = utils.SmartUnicode(dentry_.d_name.name.deref())
            path_components = [component] + path_components
            dentry_ = dentry_.d_parent

        result = '/'.join(filter(None, path_components))

        if result.startswith(("socket:", "pipe:")):
            if result.find("]") == -1:
                result += ":[{0}]".format(self.d_inode.i_ino)

        elif result != "inotify":
            result = '/' + result

        return result


class task_struct(obj.Struct):

    @utils.safe_property
    def commandline(self):
        if self.mm:
            # The argv string is initialized inside the process's address space.
            proc_as = self.get_process_address_space()

            # read argv from userland
            argv = proc_as.read(self.mm.arg_start,
                                self.mm.arg_end - self.mm.arg_start)

            if argv:
                # split the \x00 buffer into args
                name = " ".join(argv.split("\x00"))
            else:
                name = ""
        else:
            # kernel thread
            name = "[" + self.comm + "]"

        return name

    @utils.safe_property
    def task_start_time(self):
        if self.obj_profile.get_constant("tk_core"):
            # Kernel 3.17 changes how start_time is stored. Now it's
            # in nsecs monotonic or boot based.
            start_timespec = self.obj_profile.timespec()
            start_timespec.tv_sec = self.m("start_time") / 1000000000
            start_timespec.tv_nsec = self.m("start_time") % 1000000000
            boot_time = self.obj_profile.getboottime()
            start_time = self.obj_profile.UnixTimeStamp(
                value = start_timespec.tv_sec - boot_time.tv_sec)
            return start_time
        return self.m("start_time").as_timestamp()

    def get_path(self, filp):
        """Resolve the dentry, vfsmount relative to this task's chroot.

        Returns:
          An absolute path to the global filesystem mount. (I.e. we do not
          truncate the path at the chroot point as the kernel does).
        """
        # The specific implementation depends on the kernel version.

        # Newer kernels have mnt_parent in the mount struct, not in the
        # vfsmount struct.
        if self.obj_profile.get_obj_offset("vfsmount", "mnt_parent"):
            return vfs.Linux26VFS(self.obj_profile).get_path(self, filp)

        else:
            return vfs.Linux3VFS(self.obj_profile).get_path(self, filp)

    def get_process_address_space(self):
        directory_table_base = self.obj_vm.vtop(self.mm.pgd.v())

        try:
            process_as = self.obj_vm.__class__(
                base=self.obj_vm.base, session=self.obj_vm.session,
                dtb=directory_table_base, profile=self.obj_profile)

        except AssertionError:
            return obj.NoneObject("Unable to get process AS")

        process_as.name = "Process {0}".format(self.pid)

        return process_as


class timespec(obj.Struct):
    # The following calculates the number of ns each tick is.
    # http://lxr.free-electrons.com/source/include/linux/jiffies.h?v=2.6.32#L12

    # The HZ value should be obtained from the auxilary vector but for now we
    # hard code it. TODO: http://lwn.net/Articles/519085/
    HZ = 1000

    # The clock frequency of the i8253/i8254 PIT
    CLOCK_TICK_RATE = PIT_TICK_RATE = 1193182

    # LATCH is used in the interval timer and ftape setup.
    LATCH = ((CLOCK_TICK_RATE + HZ/2) / HZ)

    # HZ is the requested value. ACTHZ is actual HZ
    ACTHZ = (CLOCK_TICK_RATE / LATCH)

    # TICK_NSEC is the time between ticks in nsec assuming real ACTHZ
    TICK_NSEC = 1000000 * 1000 /  ACTHZ

    NSEC_PER_SEC = 1000000000

    def __init__(self, *args, **kwargs):
        super(timespec, self).__init__(*args, **kwargs)
        self.HZ = self.obj_profile.get_kernel_config("CONFIG_HZ") or self.HZ

    def __add__(self, other):
        if not isinstance(other, self.__class__):
            raise TypeError("Can only add timespec to timespec")

        sec = other.tv_sec + self.tv_sec
        nsec = other.tv_nsec + self.tv_nsec

        result = self.obj_profile.timespec()
        result.tv_sec = sec
        result.tv_nsec = nsec

        return result

    def __sub__(self, other):
        ts = self.obj_profile.timespec()
        ts.tv_sec = -other.tv_sec
        ts.tv_nsec = -other.tv_nsec
        return self + ts

    def normalized_timespec(self):
        """Normalizes a timespec's secs and nsecs.

        Based on set_normalized_timespec:
          http://lxr.free-electrons.com/source/kernel/time.c?v=3.11#L358
        """
        sec = self.tv_sec + self.tv_nsec / self.NSEC_PER_SEC
        nsec = self.tv_nsec % self.NSEC_PER_SEC

        result = self.obj_profile.timespec()
        result.tv_sec = sec
        result.tv_nsec = nsec
        return result

    def as_timestamp(self):
        """Returns the time as a UnixTimestamp."""
        the_time = self - self.obj_profile.getboottime(vm=self.obj_vm)
        the_time = the_time.normalized_timespec()
        return self.obj_profile.UnixTimeStamp(value=the_time.tv_sec.v())


class net_device(obj.Struct):
    @utils.safe_property
    def mac_addr(self):
        addr = self.perm_addr
        if (addr.obj_vm.read(addr.obj_offset, addr.obj_size) ==
                "\x00" * addr.obj_size):
            addr = self.dev_addr.deref()

        return addr.cast("MacAddress")


class PermissionFlags(basic.Flags):
    """A Flags object for printing vm_area_struct permissions
    in a format like rwx or r-x"""

    def __unicode__(self):
        result = []
        value = self.v()
        for k, v in sorted(self.maskmap.items()):
            if value & v:
                result.append(k)
            else:
                result.append("-")

        return ''.join(result)

    def is_flag(self, flag):
        return self.v() & (1 << self.bitmap[flag])

    def is_executable(self):
        return self.is_flag('x')

    def is_readable(self):
        return self.is_flag('r')

    def is_writable(self):
        return self.is_flag('w')


class kgid_t(obj.Struct):
    """Newer kernels use this struct instead of an int."""

    def __unicode__(self):
        return unicode(self.val)

    def __long__(self):
        return long(self.val)


class kuid_t(kgid_t):
    """Newer kernels use this struct instead of an int."""


class proc_dir_entry(obj.Struct):
    @utils.safe_property
    def Name(self):
        if self.name.obj_type == "Pointer":
            return self.name.deref().cast("String", length=self.namelen)
        else:
            return self.name.cast("String", length=self.namelen)


class page(obj.Struct):
    def physical_offset(self):
        """The physical offset of the page represented by this page struct."""

        # mem_map is used in 32-bit kernels.
        mem_map = self.obj_profile.get_constant_object(
            "mem_map", "Pointer")

        if mem_map == None:
            if self.obj_profile.get_constant("mem_section"):
                # The VMEMMAP starts at this address in 64-bit kernels.
                # arch/x86/include/asm/pgtable_64_types.h
                mem_map = obj.Pointer.integer_to_address(0xffffea0000000000)
            else:
                self.obj_session.logging.error(
                    "Unable to determine physical address of page. NUMA is not "
                    "supported.")
                return obj.NoneObject("NUMA is unsupported.")

        # Linux stores an array of struct page starting at mem_map.
        # To find the physical address of a given page, we need to find its
        # index within the array which corresponds to the Page Frame Number
        # and shift it left by the PAGE_SIZE.
        pfn = (self.obj_offset - mem_map) / self.obj_size
        phys_offset = pfn << 12
        return phys_offset

    def read(self, offset, size):
        """Reads data from the physical page associated to this page entry.

        It reads PAGE_SIZE at max.
        """

        phys_offset = self.physical_offset()
        phys_as = self.obj_session.physical_address_space
        to_read = max(0, self.obj_vm.PAGE_SIZE - offset)
        to_read = min(size, to_read)
        if to_read:
            data = phys_as.read(phys_offset, to_read)
        if to_read <= size:
            data += "\x00" * (size - to_read)
        return data


class InodePermission(basic.Flags):
    def __getattr__(self, attr):
        mask = super(InodePermission, self).__getattr__(attr)
        if not mask:
            return obj.NoneObject("Mask {0} not known".format(attr))

        if attr.startswith("S_IF"):
            return (self.v() & 0xF000) == mask
        return self.v() & mask


class Linux(basic.RelativeOffsetMixin, basic.BasicClasses):
    METADATA = dict(
        os="linux",
        type="Kernel")

    image_base = 0

    @classmethod
    def Initialize(cls, profile):
        super(Linux, cls).Initialize(profile)
        profile.add_classes(dict(
            InodePermission=InodePermission,
            PermissionFlags=PermissionFlags,
            dentry=dentry,
            hlist_head=hlist_head,
            hlist_node=hlist_node,
            list_head=list_head,
            net_device=net_device,
            page=page, kgid_t=kgid_t, kuid_t=kuid_t,
            proc_dir_entry=proc_dir_entry,
            task_struct=task_struct,
            timespec=timespec, inet_sock=inet_sock,
            ))
        profile.add_overlay(linux_overlay)
        profile.add_constants(dict(default_text_encoding="utf8"))

        # Autoguessing for old profiles that don't provide an arch.
        if not profile.metadata("arch"):
            try:
                profile.constant_addresses.find_gt(2**32)
                profile.set_metadata("arch", "AMD64")
            except ValueError:
                profile.set_metadata("arch", "I386")

        if profile.metadata("arch") == "I386":
            basic.Profile32Bits.Initialize(profile)
            try:
                if (not profile.metadata("pae") and
                        profile.get_kernel_config("CONFIG_X86_PAE") == "y"):
                    profile.set_metadata("pae", True)
            except ValueError:
                pass

        # ARM systems are just normal 32 bit systems with a weird MMU. Per
        # http://elinux.org/images/6/6a/Elce11_marinas.pdf, there's also LPAE
        # but we do not support this.
        elif profile.metadata("arch") == "ARM":
            basic.Profile32Bits.Initialize(profile)

        elif profile.metadata("arch") == "MIPS":
            basic.ProfileMIPS32Bits.Initialize(profile)

        elif profile.metadata("arch") == "AMD64":
            basic.ProfileLP64.Initialize(profile)

    def GetImageBase(self):
        if not self.image_base:
            self.image_base = obj.Pointer.integer_to_address(
                self.session.GetParameter("kernel_slide", 0))
        return self.image_base

    def _SetupProfileFromData(self, data):
        """Sets up the kernel profile, adding kernel config options."""
        super(Linux, self)._SetupProfileFromData(data)
        self.kernel_config_options = {}

        # Add the kernel configuration
        config = data.get("$CONFIG")
        if config:
            self.add_kernel_config_options(**config)

        try:
            # Set the pae flag if we're a 32bit PAE profile
            if (self.get_kernel_config("CONFIG_X86_PAE") == "y" and
                    self.metadata("arch") == "I386"):
                self.set_metadata("pae", True)
        except ValueError:
            # We cannot autoguess PAE at the moment if we don't know the config
            # option value for it.
            self.session.logging.debug(
                "No kernel config available in the profile, so we cannot "
                "detect PAE.")

    def add_kernel_config_options(self, **kwargs):
        """Add the kwargs as kernel config options for this profile."""
        for k, v in kwargs.iteritems():
            self.kernel_config_options[k] = v

    def get_kernel_config(self, config_option):
        """Returns the kernel config option config_option for this profile.

        Raises if no kernel configuration is present in the profile.
        """

        config_options = getattr(self, "kernel_config_options", obj.NoneObject(
            "No kernel config options present in the profile."))

        return config_options.get(config_option)

    def get_wall_to_monotonic(self, vm=None):
        wall_addr = self.get_constant("wall_to_monotonic")
        if wall_addr:
            return self.timespec(vm=vm, offset=wall_addr)

        # After Kernel 3.3 wall_to_monotonic is stored inside the timekeeper.
        timekeeper_addr = self.get_constant("timekeeper")
        if timekeeper_addr:
            return  self.timekeeper(
                vm=vm, offset=timekeeper_addr).wall_to_monotonic

    def get_total_sleep_time(self, vm=None):
        total_sleep_time_addr = self.get_constant(
            "total_sleep_time")

        if total_sleep_time_addr:
            return self.timespec(
                vm=vm, offset=total_sleep_time_addr)

        # After Kernel 3.3 wall_to_monotonic is stored inside the timekeeper.
        timekeeper_addr = self.get_constant("timekeeper")
        if timekeeper_addr:
            return  self.timekeeper(
                vm=vm, offset=timekeeper_addr).total_sleep_time

        # Just return an empty timespec.
        return self.timespec()

    def getboottime(self, vm=None):
        """Returns the real time of system boot."""
        if self.get_constant("tk_core"):
            tk_core = self.get_constant_object("tk_core", "tk_core")
            tk = tk_core.timekeeper
            t = self.ktime_sub(tk.offs_real, tk.offs_boot)
            return self.ktime_to_timespec(t)
        else:
            boottime = (self.get_wall_to_monotonic(vm=vm) +
                        self.get_total_sleep_time(vm=vm))
            return boottime.normalized_timespec()

    def ktime_sub(self, lhs, rhs):
        """Substracts two ktime_t instances."""
        kt = self.ktime()
        kt.tv64 = lhs.tv64 - rhs.tv64
        return kt

    def ktime_to_timespec(self, kt):
        """Transforms a ktime_t to a timespec."""
        return self.ns_to_timespec(kt.tv64)

    def ns_to_timespec(self, nsec):
        """Transforms nanoseconds to a timespec."""
        ts = self.timespec()

        if not nsec:
            ts.tv_sec = 0
            ts.tv_nsec = 0
        else:
            tv_sec = nsec / timespec.NSEC_PER_SEC
            rem = nsec % timespec.NSEC_PER_SEC
            ts.tv_sec = tv_sec

            if rem < 0:
                ts.tv_sec -= 1
                rem += timespec.NSEC_PER_SEC

            ts.tv_nsec = rem
        return ts

    def phys_addr(self, va):
        """Returns the physical address of a given virtual address va.

        Linux has a direct mapping between the kernel virtual address space and
        the physical memory. This is the difference between the virtual and
        physical addresses (aka PAGE_OFFSET). This is defined by the __va macro:

        #define __va(x) ((void *)((unsigned long) (x) + PAGE_OFFSET))
        """
        va_addr = obj.Pointer.integer_to_address(va)
        page_offset_addr = obj.Pointer.integer_to_address(
            self.GetPageOffset())

        if va_addr >= page_offset_addr:
            return (va_addr - page_offset_addr)
        else:
            return obj.NoneObject("Unable to translate VA 0x%x", va)

    def GetPageOffset(self):
        """Gets the page offset."""
        # This calculation needs to be here instead of the LinuxPageOffset
        # parameter hook because it is used during profile autodetection, where
        # a profile is not yet set on the session object.
        self.session.logging.debug("Calculating page offset...")

        if self.metadata("arch") == "I386":
            return (self.get_constant("_text", False) -
                    self.get_constant("phys_startup_32", False))

        elif self.metadata("arch") == "AMD64":
            # We use the symbol phys_startup_64. If it's not present in the
            # profile and it's different than the default, we should be able
            # to autodetect the difference via kernel_slide.
            phys_startup_64 = (self.get_constant("phys_startup_64", False) or
                               0x1000000)

            return self.get_constant("_text", False) - phys_startup_64

        elif self.metadata("arch") == "MIPS":
            return 0x80000000

        elif self.metadata("arch") == "ARM":
            # This might not be always the same. According to arm/Kconfig,
            # this only seems to be accurate with the default split in linux
            # (VMSPLIT_3G). See arm/Kconfig. TODO: Use the VMSPLIT_3G config
            # variable here.

            # 1563 config PAGE_OFFSET
            # 1564         hex
            # 1565         default PHYS_OFFSET if !MMU
            # 1566         default 0x40000000 if VMSPLIT_1G
            # 1567         default 0x80000000 if VMSPLIT_2G
            # 1568         default 0xC0000000

            return 0xc0000000

        else:
            return obj.NoneObject("No profile architecture set.")

    def nsec_to_clock_t(self, x):
        """Convers nanoseconds to a clock_t. Introduced in 3.17.

        http://lxr.free-electrons.com/source/kernel/time/time.c?v=3.17#L703
        """
        NSEC_PER_SEC = 1000000000L
        USER_HZ = 100

        if NSEC_PER_SEC % USER_HZ == 0:
            return x / (NSEC_PER_SEC / USER_HZ)
        elif USER_HZ % 512 == 0:
            return ((x * USER_HZ) / 512) / (NSEC_PER_SEC / 512)
        else:
            return (x*9) / ((9 * NSEC_PER_SEC + (USER_HZ/2)) / USER_HZ)


# Legacy for old profiles
class Linux32(Linux):
    pass


class Linux64(Linux):
    @classmethod
    def Initialize(cls, profile):
        profile.set_metadata("arch", "AMD64")
        super(Linux64, cls).Initialize(profile)


class LinuxConfigProfileLoader(obj.ProfileSectionLoader):
    """Linux profiles can carry the original Kconfig in the $CONFIG section."""
    name = "$CONFIG"

    def LoadIntoProfile(self, session, profile, config):
        profile.kernel_config_options = config

        return profile
