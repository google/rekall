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

import logging

from rekall import obj
from rekall import utils

from rekall.plugins.overlays import basic
from rekall.plugins.overlays.linux import vfs


linux_overlay = {
    'task_struct' : [None, {
        'name': lambda x: x.comm,
        'comm': [None, ['UnicodeString', dict(length=16)]],
        'uid': lambda x: x.m("uid") or x.cred.uid,
        'gid': lambda x: x.m("gid") or x.cred.gid,
        'euid': lambda x: x.m("euid") or x.cred.euid,
        }],

    'module' : [None, {
        'name': [None, ['UnicodeString', dict(length=60)]],
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

            'mac_addr': lambda x: (x.perm_addr or x.dev_addr).cast(
                "MacAddress"),

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
            'message': [lambda x: x.flags.obj_offset + x.flags.size(),
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

    'qstr': [None, {
            'name': [None, ['Pointer', dict(
                        target='UnicodeString',
                        target_args=dict(
                            length=lambda x: x.m("len") or x.u1.u1.len,
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
    "proc_dir_entry": [None, {
            'Name': lambda x: (
                # 2.6 kernel.
                x.name.cast("Pointer", target="String").deref() or

                # 3.x kernel.
                x.name.cast("String")),
            }],

    "kobject": [None, {
            'name': [None, ["Pointer", dict(
                        target="String",
                        target_args=dict(length=32),
                        )]],
            }],

    'gate_struct64': [None, {
            'Address': lambda x: (x.offset_low |
                                  x.offset_middle << 16 |
                                  x.offset_high << 32),
            }],

    'desc_struct': [None, {
            'Address': lambda x: (x.b & 0xffff0000) | (x.a & 0x0000ffff),
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
                        choices={1:"SOCK_STREAM",
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
                        choices={
                            1:"TCP_ESTABLISHED",
                            2:"TCP_SYN_SENT",
                            3:"TCP_SYN_RECV",
                            4:"TCP_FIN_WAIT1",
                            5:"TCP_FIN_WAIT2",
                            6:"TCP_TIME_WAIT",
                            7:"TCP_CLOSE",
                            8:"TCP_CLOSE_WAIT",
                            9:"TCP_LAST_ACK",
                            10:"TCP_LISTEN",
                            11:"TCP_CLOSING",
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
    }


class list_head(basic.ListMixIn, obj.Struct):
    """A list_head makes a doubly linked list."""
    _forward = "next"
    _backward = "prev"


class hlist_head(obj.Struct):
    def list_of_type(self, type, member):
        hlist = self.first.deref()
        while hlist:
            yield basic.container_of(hlist, type, member)

            hlist = hlist.next


class inet_sock(obj.Struct):
    """Class for an internet socket object"""

    @property
    def src_port(self):
        return (self.m("sport") or self.m("inet_sport")).cast(
            "unsigned be short")

    @property
    def dst_port(self):
        return (self.m("dport") or self.m("inet_dport")).cast(
            "unsigned be short") or self.sk.m("__sk_common").u3.u1.skc_dport

    @property
    def src_addr(self):
        if self.sk.m("__sk_common").skc_family == "AF_INET":
            return (self.m("rcv_saddr") or self.m("inet_rcv_saddr") or
                    self.sk.m("__sk_common").u1.u1.skc_rcv_saddr).cast(
                "Ipv4Address")

        else:
            return self.pinet6.saddr.cast("Ipv6Address")

    @property
    def dst_addr(self):
        if self.sk.m("__sk_common").skc_family == "AF_INET":
            return (self.m("daddr") or self.m("inet_daddr") or
                    self.sk.m("__sk_common").u1.u1.skc_daddr).cast(
                "Ipv4Address")

        else:
            return self.pinet6.daddr.cast("Ipv6Address")


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
    @property
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

    @property
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

    def get_path(self, filp):
        """Resolve the dentry, vfsmount relative to this task's chroot.

        Returns:
          An absolute path to the global filesystem mount. (I.e. we do not
          truncate the path at the chroot point as the kernel does).
        """
        # The specific implementation depends on the kernel version.
        try:
            # Newer kernels have mnt_parent in the mount struct, not in the
            # vfsmount struct.
            self.obj_profile.get_obj_offset("vfsmount", "mnt_parent")

            return vfs.Linux26VFS().get_path(self, filp)
        except KeyError:
            return vfs.Linux3VFS().get_path(self, filp)

    def get_process_address_space(self):
        directory_table_base = self.obj_vm.vtop(self.mm.pgd.v())

        try:
            process_as = self.obj_vm.__class__(
                base=self.obj_vm.base, session=self.obj_vm.session,
                dtb=directory_table_base)

        except AssertionError, _e:
            return obj.NoneObject("Unable to get process AS")

        process_as.name = "Process {0}".format(self.pid)

        return process_as


class timespec(obj.Struct):
    # The following calculate the number of ns each tick is.
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

    @property
    def wall_to_monotonic(self):
        wall_addr = self.obj_profile.get_constant("wall_to_monotonic")
        if wall_addr:
            return self.obj_profile.timespec(vm=self.obj_vm, offset=wall_addr)

        # After Kernel 3.3 wall_to_monotonic is stored inside the timekeeper.
        timekeeper_addr = self.obj_profile.get_constant("timekeeper")
        if timekeeper_addr:
            return  self.obj_profile.timekeeper(
                vm=self.obj_vm, offset=timekeeper_addr).wall_to_monotonic

    @property
    def total_sleep_time(self):
        total_sleep_time_addr = self.obj_profile.get_constant(
            "total_sleep_time")

        if total_sleep_time_addr:
            return self.obj_profile.timespec(
                vm=self.obj_vm, offset=total_sleep_time_addr)

        # After Kernel 3.3 wall_to_monotonic is stored inside the timekeeper.
        timekeeper_addr = self.obj_profile.get_constant("timekeeper")
        if timekeeper_addr:
            return  self.obj_profile.timekeeper(
                vm=self.obj_vm, offset=timekeeper_addr).total_sleep_time

        # Just return an empty timespec.
        return self.obj_profile.timespec()

    def __add__(self, other):
        """Properly normalize this object from sec and nsec.

        based on set_normalized_timespec function.
        """
        if not isinstance(other, self.__class__):
            raise TypeError("Can only add timespec to timespec")

        sec = other.tv_sec + self.tv_sec
        nsec = other.tv_nsec + self.tv_nsec

        sec += nsec / self.NSEC_PER_SEC
        nsec = nsec % self.NSEC_PER_SEC

        result = self.obj_profile.timespec()
        result.tv_sec = sec
        result.tv_nsec = nsec

        return result

    def getboottime(self):
        result = self.wall_to_monotonic + self.total_sleep_time
        return result.tv_sec + result.tv_nsec / self.NSEC_PER_SEC

    def as_timestamp(self):
        secs = self.tv_sec + self.tv_nsec / self.NSEC_PER_SEC
        return self.obj_profile.UnixTimeStamp(value=secs)


class PermissionFlags(basic.Flags):
    """A Flags object for printing vm_area_struct permissions
    in a format like rwx or r-x"""

    def __str__(self):
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


class Linux(basic.BasicClasses):
    METADATA = dict(
        os="linux",
        type="Kernel")

    @classmethod
    def Initialize(cls, profile):
        super(Linux, cls).Initialize(profile)
        profile.add_classes(dict(
                list_head=list_head, hlist_head=hlist_head,
                dentry=dentry,
                task_struct=task_struct,
                timespec=timespec, inet_sock=inet_sock,
                PermissionFlags=PermissionFlags,
                ))
        profile.add_overlay(linux_overlay)
        profile.add_constants(default_text_encoding="utf8")

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
        elif profile.metadata("arch") == "AMD64":
            basic.ProfileLP64.Initialize(profile)

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
        except ValueError, e:
            # We cannot autoguess PAE at the moment if we don't know the config
            # option value for it.
            logging.debug(("No kernel config available in the profile, so "
                           "we cannot detect PAE."))
            pass

    def add_kernel_config_options(self, **kwargs):
        """Add the kwargs as kernel config options for this profile."""
        for k, v in kwargs.iteritems():
            self.kernel_config_options[k] = v

    def get_kernel_config(self, config_option):
        """Returns the kernel config option config_option for this profile.

        Raises if no kernel configuration is present in the profile.
        """
        if not self.kernel_config_options:
            raise ValueError("No kernel config options present in the profile.")
        return self.kernel_config_options.get(config_option)


# Legacy for old profiles
class Linux32(Linux):
    pass


class Linux64(Linux):
    pass
