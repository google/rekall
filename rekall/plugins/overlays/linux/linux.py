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
import logging
import json
import posixpath
import re
import sys
import zipfile
import StringIO

from rekall import obj
from rekall import plugin
from rekall import utils

from rekall.plugins.overlays import basic
from rekall.plugins.overlays.linux import vfs
from rekall.plugins.overlays.linux import dwarfdump

# Try to use the elftools directly if they are present.
try:
    from rekall.plugins.overlays.linux import dwarfparser

    logging.info("Unable to load the dwarfparser module. Do you have "
                 "elftools installed?")
except ImportError:
    dwarfparser = None

linux_overlay = {
    'task_struct' : [None, {
            'comm': [None , ['UnicodeString', dict(length = 16)]],
            'uid': lambda x: x.m("uid") or x.cred.uid,
            'gid': lambda x: x.m("gid") or x.cred.gid,
            'euid': lambda x: x.m("euid") or x.cred.euid,
            }],

    'module' : [None, {
            'name': [None , ['UnicodeString', dict(length = 60)]],
            'kp': [None, ['Pointer', dict(
                        target='Array',
                        target_args=dict(
                            target='kernel_param',
                            count=lambda x: x.num_kp))]],
            }],

    'kernel_param': [None, {
            'name' : [None , ['Pointer', dict(target='UnicodeString')]],
            'getter_addr': lambda x: (x.m("get") or x.ops.get),
            }],

    'kparam_array': [None, {
            'getter_addr': lambda x: (x.m("get") or x.ops.get),
            }],

    'super_block' : [None, {
        's_id' : [None , ['UnicodeString', dict(length = 32)]],
        'major': lambda x: x.s_dev >> 20,
        'minor': lambda x: x.s_dev & ((1 << 20) - 1),
        }],

    'net_device'  : [None, {
            # Flags defined in include/linux/if.h
            'flags': [None, ['Flags', dict(
                        maskmap={
                            "IFF_UP":           0x1,  # interface is up
                            "IFF_BROADCAST":    0x2,  # broadcast address valid
                            "IFF_DEBUG":        0x4,  # turn on debugging
                            "IFF_LOOPBACK":     0x8,  # is a loopback net
                            "IFF_POINTOPOINT": 0x10,  # interface is has p-p link
                            "IFF_NOTRAILERS":  0x20,  # avoid use of trailers
                            "IFF_RUNNING":     0x40,  # interface RFC2863 OPER_UP
                            "IFF_NOARP":       0x80,  # no ARP protocol
                            "IFF_PROMISC":     0x100, # receive all packets
                            "IFF_ALLMULTI":    0x200,
                            }
                        )]],

            'name' : [None , ['UnicodeString', dict(length = 16)]],

            'mac_addr': lambda x: (x.perm_addr or x.dev_addr).cast("MacAddress"),

            'ip_ptr': [None, ['Pointer', dict(target="in_device")]],
            }],

    'in_ifaddr': [None, {
            'ifa_address': [None, ['IpAddress']],
            'ifa_label': [None, ['String']],
            }],

    'sockaddr_un' : [None, {
        'sun_path'      : [ None , ['UnicodeString', dict(length =108)]],
        }],

    'cpuinfo_x86' : [None, {
        'x86_model_id'  : [ None , ['UnicodeString', dict(length = 64)]],
        'x86_vendor_id' : [ None,  ['UnicodeString', dict(length = 16)]],
        }],

    'module_sect_attr': [None, {
            'name': [None, ['Pointer', dict(target='UnicodeString')]]
            }],

    # The size of the log record is stored in the len member.
    'log': [lambda x: x.len, {
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

    'vm_area_struct' : [ None, {
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
                            0:"IPPROTO_HOPOPT",               # Dummy protocol forTCP
                            1:"IPPROTO_ICMP",             # Internet Control Message Protocol
                            2:"IPPROTO_IGMP",             # Internet Group Management Protocol
                            4:"IPPROTO_IPV4",             # IPIP tunnels (older KA9Q tunnels use 94)
                            6:"IPPROTO_TCP",              # Transmission Control Protocol
                            8:"IPPROTO_EGP",              # Exterior Gateway Protocol
                            12:"IPPROTO_PUP",             # PUP protocol
                            17:"IPPROTO_UDP",             # User Datagram Protocol
                            22:"IPPROTO_IDP",             # XNS IDP protocol
                            29:"IPPROTO_TP",              # SO Transport Protocol Class 4
                            33:"IPPROTO_DCCP",            # Datagram Congestion Control Protocol
                            41:"IPPROTO_IPV6",            # IPv6-in-IPv4 tunnelling
                            46:"IPPROTO_RSVP",            # RSVP Protocol
                            47:"IPPROTO_GRE",             # Cisco GRE tunnels (rfc 1701",1702)
                            50:"IPPROTO_ESP",             # Encapsulation Security Payload protocol
                            51:"IPPROTO_AH",              # Authentication Header protocol
                            92:"IPPROTO_MTP",             # Multicast Transport Protocol
                            94:"IPPROTO_BEETPH",          # IP option pseudo header for BEET
                            98:"IPPROTO_ENCAP",           # Encapsulation Header
                            103:"IPPROTO_PIM",            # Protocol Independent Multicast
                            108:"IPPROTO_COMP",           # Compression Header Protocol
                            132:"IPPROTO_SCTP",           # Stream Control Transport Protocol
                            136:"IPPROTO_UDPLITE",        # UDP-Lite (RFC 3828)
                            255:"IPPROTO_RAW",            # Raw IP packets
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
                        # Partial List
                        # from: http://lxr.free-electrons.com/source/include/linux/socket.h#L140
                        choices={
                            0:"AF_UNSPEC",
                            1:"AF_UNIX",        # Unix domain sockets
                            2:"AF_INET",        # Internet IP Protocol
                            3:"AF_AX25",        # Amateur Radio AX.25
                            4:"AF_IPX",         # Novell IPX
                            5:"AF_APPLETALK",   # AppleTalk DDP
                            7:"AF_BRIDGE",      # Multiprotocol bridge
                            10:"AF_INET6",      # IP version 6
                            },
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
                "IpAddress")

        else:
            return self.pinet6.saddr.cast("Ipv6Address")

    @property
    def dst_addr(self):
        if self.sk.m("__sk_common").skc_family == "AF_INET":
            return (self.m("daddr") or self.m("inet_daddr") or
                    self.sk.m("__sk_common").u1.u1.skc_daddr).cast(
                "IpAddress")

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
        dentry = self

        path_components = []

        # Check for deleted dentry.
        if self.d_flags.DCACHE_UNHASHED and not self.is_root:
            return " (deleted) "

        while len(path_components) < 50:
            if dentry.is_root:
                break

            component = utils.SmartUnicode(dentry.d_name.name.deref())
            path_components = [component] + path_components
            dentry = dentry.d_parent

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
                dtb = directory_table_base)

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
        total_sleep_time_addr = self.obj_profile.get_constant("total_sleep_time")
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


class Linux32(basic.Profile32Bits, basic.BasicWindowsClasses):
    """A Linux profile which works with dwarfdump output files."""
    _md_os = "linux"
    _md_memory_model = "32bit"
    _md_type = "Kernel"

    def __init__(self, **kwargs):
        super(Linux32, self).__init__(**kwargs)
        self.add_classes(dict(
                list_head=list_head, hlist_head=hlist_head,
                dentry=dentry,
                task_struct=task_struct,
                timespec=timespec, inet_sock=inet_sock,
                PermissionFlags=PermissionFlags,
                ))
        self.add_overlay(linux_overlay)
        self.add_constants(default_text_encoding="utf8")

class Linux64(basic.ProfileLP64, Linux32):
    """Support for 64 bit linux systems."""
