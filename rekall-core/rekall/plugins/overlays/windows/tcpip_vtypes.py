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
#
import socket

from rekall import kb
from rekall import obj
from rekall import utils
from rekall.plugins.overlays import basic
from rekall.plugins.overlays.windows import pe_vtypes


AF_INET = 2
AF_INET6 = 0x17

# String representations of INADDR_ANY and INADDR6_ANY
inaddr_any = utils.inet_ntop(socket.AF_INET, '\0' * 4)
inaddr6_any = utils.inet_ntop(socket.AF_INET6, '\0' * 16)

protos = {
    0:"HOPOPT",
    1:"ICMP",
    2:"IGMP",
    3:"GGP",
    4:"IPv4",
    5:"ST",
    6:"TCP",
    7:"CBT",
    8:"EGP",
    9:"IGP",
    10:"BBN-RCC-MON",
    11:"NVP-II",
    12:"PUP",
    13:"ARGUS",
    14:"EMCON",
    15:"XNET",
    16:"CHAOS",
    17:"UDP",
    18:"MUX",
    19:"DCN-MEAS",
    20:"HMP",
    21:"PRM",
    22:"XNS-IDP",
    23:"TRUNK-1",
    24:"TRUNK-2",
    25:"LEAF-1",
    26:"LEAF-2",
    27:"RDP",
    28:"IRTP",
    29:"ISO-TP4",
    30:"NETBLT",
    31:"MFE-NSP",
    32:"MERIT-INP",
    33:"DCCP",
    34:"3PC",
    35:"IDPR",
    36:"XTP",
    37:"DDP",
    38:"IDPR-CMTP",
    39:"TP++",
    40:"IL",
    41:"IPv6",
    42:"SDRP",
    43:"IPv6-Route",
    44:"IPv6-Frag",
    45:"IDRP",
    46:"RSVP",
    47:"GRE",
    48:"DSR",
    49:"BNA",
    50:"ESP",
    51:"AH",
    52:"I-NLSP",
    53:"SWIPE",
    54:"NARP",
    55:"MOBILE",
    56:"TLSP",
    57:"SKIP",
    58:"IPv6-ICMP",
    59:"IPv6-NoNxt",
    60:"IPv6-Opts",
    61:"Host-interal",
    62:"CFTP",
    63:"Local Network",
    64:"SAT-EXPAK",
    65:"KRYPTOLAN",
    66:"RVD",
    67:"IPPC",
    68:"Dist-FS",
    69:"SAT-MON",
    70:"VISA",
    71:"IPCV",
    72:"CPNX",
    73:"CPHB",
    74:"WSN",
    75:"PVP",
    76:"BR-SAT-MON",
    77:"SUN-ND",
    78:"WB-MON",
    79:"WB-EXPAK",
    80:"ISO-IP",
    81:"VMTP",
    82:"SECURE-VMTP",
    83:"VINES",
    84:"TTP",
    # 84:"IPTM",
    85:"NSFNET-IGP",
    86:"DGP",
    87:"TCF",
    88:"EIGRP",
    89:"OSPFIGP",
    90:"Sprite-RPC",
    91:"LARP",
    92:"MTP",
    93:"AX.25",
    94:"IPIP",
    95:"MICP",
    96:"SCC-SP",
    97:"ETHERIP",
    98:"ENCAP",
    99:"Encryption",
    100:"GMTP",
    101:"IFMP",
    102:"PNNI",
    103:"PIM",
    104:"ARIS",
    105:"SCPS",
    106:"QNX",
    107:"A/N",
    108:"IPComp",
    109:"SNP",
    110:"Compaq-Peer",
    111:"IPX-in-IP",
    112:"VRRP",
    113:"PGM",
    114:"0-hop",
    115:"L2TP",
    116:"DDX",
    117:"IATP",
    118:"STP",
    119:"SRP",
    120:"UTI",
    121:"SMP",
    122:"SM",
    123:"PTP",
    124:"ISIS over IPv4",
    125:"FIRE",
    126:"CRTP",
    127:"CRUDP",
    128:"SSCOPMCE",
    129:"IPLT",
    130:"SPS",
    131:"PIPE",
    132:"SCTP",
    133:"FC",
    134:"RSVP-E2E-IGNORE",
    135:"Mobility Header",
    136:"UDPLite",
    137:"MPLS-in-IP",
    138:"manet",
    139:"HIP",
    140:"Shim6",
    141:"WESP",
    142:"ROHC",
    253:"Experimental",
    254:"Experimental",
    255:"Reserved",
}

# Structures used by connections, connscan, sockets, sockscan.
# Used by x86 XP (all service packs) and x86 2003 SP0.
tcpip_vtypes = {
    '_ADDRESS_OBJECT' : [0x68, {
        'Next' : [0x0, ['pointer', ['_ADDRESS_OBJECT']]],
        'LocalIpAddress' : [0x2c, ['Ipv4Address']],
        'LocalPort' : [0x30, ['unsigned be short']],
        'Protocol'  : [0x32, ['unsigned short']],
        'Pid' : [0x148, ['unsigned long']],
        'CreateTime' : [0x158, ['WinFileTime', {}]],
    }],
    '_TCPT_OBJECT' : [0x20, {
        'Next' : [0x0, ['pointer', ['_TCPT_OBJECT']]],
        'RemoteIpAddress' : [0xc, ['Ipv4Address']],
        'LocalIpAddress' : [0x10, ['Ipv4Address']],
        'RemotePort' : [0x14, ['unsigned be short']],
        'LocalPort' : [0x16, ['unsigned be short']],
        'Pid' : [0x18, ['unsigned long']],
    }],
}

# Structures used by connections, connscan, sockets, sockscan.
# Used by x64 XP and x64 2003 (all service packs).
tcpip_vtypes_2003_x64 = {
    '_ADDRESS_OBJECT' : [0x250, {
        'Next' : [0x0, ['pointer', ['_ADDRESS_OBJECT']]],
        'LocalIpAddress' : [0x58, ['Ipv4Address']],
        'LocalPort' : [0x5c, ['unsigned be short']],
        'Protocol'  : [0x5e, ['unsigned short']],
        'Pid' : [0x238, ['unsigned long']],
        'CreateTime' : [0x248, ['WinFileTime', {}]],
    }],
    '_TCPT_OBJECT' : [0x28, {
        'Next' : [0x0, ['pointer', ['_TCPT_OBJECT']]],
        'RemoteIpAddress' : [0x14, ['Ipv4Address']],
        'LocalIpAddress' : [0x18, ['Ipv4Address']],
        'RemotePort' : [0x1c, ['unsigned be short']],
        'LocalPort' : [0x1e, ['unsigned be short']],
        'Pid' : [0x20, ['unsigned long']],
    }],
}

# Structures used by sockets and sockscan.
# Used by x86 2003 SP1 and SP2 only.
tcpip_vtypes_2003_sp1_sp2 = {
    '_ADDRESS_OBJECT' : [0x68, {
        'Next' : [0x0, ['pointer', ['_ADDRESS_OBJECT']]],
        'LocalIpAddress' : [0x30, ['Ipv4Address']],
        'LocalPort' : [0x34, ['unsigned be short']],
        'Protocol'  : [0x36, ['unsigned short']],
        'Pid' : [0x14C, ['unsigned long']],
        'CreateTime' : [0x158, ['WinFileTime', {}]],
    }],
}

TCP_STATE_ENUM = {
    0: 'CLOSED', 1: 'LISTENING', 2: 'SYN_SENT',
    3: 'SYN_RCVD', 4: 'ESTABLISHED', 5: 'FIN_WAIT1',
    6: 'FIN_WAIT2', 7: 'CLOSE_WAIT', 8: 'CLOSING',
    9: 'LAST_ACK', 12: 'TIME_WAIT', 13: 'DELETE_TCB'
    }

# Structures used by netscan for x86 Vista and 2008 (all service packs).
tcpip_vtypes_vista = {
    '_IN_ADDR' : [None, {
        'addr4' : [0x0, ['Ipv4Address']],
        'addr6' : [0x0, ['Ipv6Address']],
    }],
    '_LOCAL_ADDRESS' : [None, {
        'pData' : [0xC, ['pointer', ['pointer', ['_IN_ADDR']]]],
    }],
    '_TCP_LISTENER': [0xa8, { # TcpL
        'Owner' : [0x18, ['pointer', ['_EPROCESS']]],
        'CreateTime' : [0x20, ['WinFileTime', {}]],
        'LocalAddr' : [0x34, ['pointer', ['_LOCAL_ADDRESS']]],
        'InetAF' : [0x38, ['pointer', ['_INETAF']]],
        "Endpoint": [0x50, ['Pointer', dict(
            target="_TCP_ENDPOINT"
        )]],
        'Port' : [0x3E, ['unsigned be short']],
    }],
    '_TCP_ENDPOINT': [0x1f0, { # TcpE
        'InetAF' : [0xC, ['pointer', ['_INETAF']]],
        'AddrInfo' : [0x10, ['pointer', ['_ADDRINFO']]],
        'ListEntry': [0x14, ['_LIST_ENTRY']],
        'State' : [0x28, ['Enumeration', dict(
            target='long',
            choices=TCP_STATE_ENUM)]],
        'LocalPort' : [0x2C, ['unsigned be short']],
        'RemotePort' : [0x2E, ['unsigned be short']],
        'Owner' : [0x160, ['pointer', ['_EPROCESS']]],
        'CreateTime' : [0, ['WinFileTime', {}]],
    }],
    '_TCP_SYN_ENDPOINT': [None, {
        'ListEntry': [8, ['_LIST_ENTRY']],
        'InetAF' : [0x18, ['pointer', ['_INETAF']]],
        'LocalPort' : [0x3c, ['unsigned be short']],
        'RemotePort' : [0x3e, ['unsigned be short']],
        'LocalAddr' : [0x1c, ['pointer', ['_LOCAL_ADDRESS']]],
        'RemoteAddress' : [0x28, ['pointer', ['_IN_ADDR']]],
        'Owner' : [0x20, ['pointer', ['_SYN_OWNER']]],
        'CreateTime' : [0, ['WinFileTime', {}]],
    }],
    '_SYN_OWNER': [None, {
        'Process': [0x18, ['pointer', ['_EPROCESS']]],
    }],
    '_TCP_TIMEWAIT_ENDPOINT': [None, {
        'ListEntry': [0x14, ['_LIST_ENTRY']],
        'InetAF' : [0xc, ['pointer', ['_INETAF']]],
        'LocalPort' : [0x1c, ['unsigned be short']],
        'RemotePort' : [0x1e, ['unsigned be short']],
        'LocalAddr' : [0x20, ['pointer', ['_LOCAL_ADDRESS']]],
        'RemoteAddress' : [0x24, ['pointer', ['_IN_ADDR']]],
        'CreateTime' : [0, ['WinFileTime', {}]],
    }],
    '_INETAF' : [None, {
        'AddressFamily' : [0xC, ['unsigned short']],
    }],
    '_ADDRINFO' : [None, {
        'Local' : [0x0, ['pointer', ['_LOCAL_ADDRESS']]],
        'Remote' : [0x8, ['pointer', ['_IN_ADDR']]],
    }],
    '_UDP_ENDPOINT': [0xa8, { # UdpA
        'Owner' : [0x18, ['pointer', ['_EPROCESS']]],
        'CreateTime' : [0x30, ['WinFileTime', {}]],
        'LocalAddr' : [0x38, ['pointer', ['_LOCAL_ADDRESS']]],
        'InetAF' : [0x14, ['pointer', ['_INETAF']]],
        'Port' : [0x48, ['unsigned be short']],
    }],

    # Reversed from tcpip.sys!TcpStartPartitionModule
    "PARTITION_TABLE": [None, {
        "Partitions": [4, ["Array", dict(
            target="Pointer",

            count=lambda x: x.obj_profile.get_constant_object(
                "PartitionCount", "unsigned int"),

            target_args=dict(
                target="Array",
                target_args=dict(
                    count=4,
                    target="FIRST_LEVEL_DIR",
                    profile=lambda x: x.session.profile,
                    )
                )
            )]],
        }],
    # ntoskrnl.exe!RtlCreateHashTable
    "FIRST_LEVEL_DIR": [0x24, {
        "SizeOfSecondLevel": [0x8, ["unsigned int"]],

        "Mask": [0x10, ["unsigned int"]],

        # Reversed from ntoskrnl.exe!RtlpAllocateSecondLevelDir
        "SecondLevel": [0x20, ["Pointer", dict(
            target="Array",
            target_args=dict(
                count=lambda x: x.SizeOfSecondLevel,
                target="_LIST_ENTRY"
                )
            )]],
        }],
}

# Structures for netscan on x86 Windows 7 (all service packs).
tcpip_vtypes_7 = {
    '_TCP_ENDPOINT': [0x210, { # TcpE
        'InetAF' : [0xC, ['pointer', ['_INETAF']]],
        'AddrInfo' : [0x10, ['pointer', ['_ADDRINFO']]],
        'ListEntry': [0x14, ['_LIST_ENTRY']],
        'State' : [0x34, ['Enumeration', dict(
            target='long', choices=TCP_STATE_ENUM)]],
        'LocalPort' : [0x38, ['unsigned be short']],
        'RemotePort' : [0x3A, ['unsigned be short']],
        'Owner' : [0x174, ['pointer', ['_EPROCESS']]],
        'CreateTime' : [0, ['WinFileTime', {}]],
    }],
    '_TCP_SYN_ENDPOINT': [None, {
        'ListEntry': [8, ['_LIST_ENTRY']],
        'InetAF' : [0x24, ['pointer', ['_INETAF']]],
        'LocalPort' : [0x48, ['unsigned be short']],
        'RemotePort' : [0x4a, ['unsigned be short']],
        'LocalAddr' : [0x28, ['pointer', ['_LOCAL_ADDRESS']]],
        'RemoteAddress' : [0x34, ['pointer', ['_IN_ADDR']]],
        'Owner' : [0x2c, ['pointer', ['_SYN_OWNER']]],
        'CreateTime' : [0, ['WinFileTime', {}]],
    }],
    '_TCP_TIMEWAIT_ENDPOINT': [None, {
        'ListEntry': [0, ['_LIST_ENTRY']],
        'InetAF' : [0x18, ['pointer', ['_INETAF']]],
        'LocalPort' : [0x28, ['unsigned be short']],
        'RemotePort' : [0x2a, ['unsigned be short']],
        'LocalAddr' : [0x2c, ['pointer', ['_LOCAL_ADDRESS']]],
        'RemoteAddress' : [0x30, ['pointer', ['_IN_ADDR']]],
        'CreateTime' : [0, ['WinFileTime', {}]],
    }],
    "_LIST_ENTRY": basic.common_overlay["LIST_ENTRY32"],
}

# Structures for netscan on x64 Vista SP0 and 2008 SP0
tcpip_vtypes_vista_64 = {
    '_IN_ADDR' : [None, {
        'addr4' : [0x0, ['Ipv4Address']],
        'addr6' : [0x0, ['Ipv6Address']],
    }],
    '_TCP_LISTENER': [0x120, { # TcpL
        'Owner' : [0x28, ['pointer', ['_EPROCESS']]],
        'CreateTime' : [0x20, ['WinFileTime', {}]],
        'LocalAddr' : [0x58, ['pointer', ['_LOCAL_ADDRESS']]],
        'InetAF' : [0x60, ['pointer', ['_INETAF']]],
        'Port' : [0x6a, ['unsigned be short']],
    }],
    '_INETAF' : [None, {
        'AddressFamily' : [0x14, ['unsigned short']],
    }],
    '_LOCAL_ADDRESS' : [None, {
        'pData' : [0x10, ['pointer', ['pointer', ['_IN_ADDR']]]],
    }],
    '_ADDRINFO' : [None, {
        'Local' : [0x0, ['pointer', ['_LOCAL_ADDRESS']]],
        'Remote' : [0x10, ['pointer', ['_IN_ADDR']]],
    }],
    '_TCP_ENDPOINT': [0x210, { # TcpE
        'InetAF' : [0x18, ['pointer', ['_INETAF']]],
        'AddrInfo' : [0x20, ['pointer', ['_ADDRINFO']]],
        'ListEntry': [0x28, ['_LIST_ENTRY']],
        'State' : [0x50, ['Enumeration', dict(
            target='long',
            choices=TCP_STATE_ENUM)]],
        'LocalPort' : [0x54, ['unsigned be short']],
        'RemotePort' : [0x56, ['unsigned be short']],
        'Owner' : [0x208, ['pointer', ['_EPROCESS']]],
        'CreateTime' : [0, ['WinFileTime', {}]],
    }],
    '_TCP_SYN_ENDPOINT': [None, {
        'ListEntry': [0x10, ['_LIST_ENTRY']],
        'InetAF' : [0x30, ['pointer', ['_INETAF']]],
        'LocalPort' : [0x64, ['unsigned be short']],
        'RemotePort' : [0x66, ['unsigned be short']],
        'LocalAddr' : [0x38, ['pointer', ['_LOCAL_ADDRESS']]],
        'RemoteAddress' : [0x50, ['pointer', ['_IN_ADDR']]],
        'Owner' : [0x40, ['pointer', ['_SYN_OWNER']]],
        'CreateTime' : [0, ['WinFileTime', {}]],
    }],
    '_SYN_OWNER': [None, {
        'Process': [0x28, ['pointer', ['_EPROCESS']]],
    }],
    '_TCP_TIMEWAIT_ENDPOINT': [None, {
        'ListEntry': [0, ['_LIST_ENTRY']],
        'InetAF' : [0x18, ['pointer', ['_INETAF']]],
        'LocalPort' : [0x30, ['unsigned be short']],
        'RemotePort' : [0x32, ['unsigned be short']],
        'LocalAddr' : [0x38, ['pointer', ['_LOCAL_ADDRESS']]],
        'RemoteAddress' : [0x40, ['pointer', ['_IN_ADDR']]],
        'CreateTime' : [0, ['WinFileTime', {}]],
    }],
    '_UDP_ENDPOINT': [0x82, { # UdpA
        'Owner' : [0x28, ['pointer', ['_EPROCESS']]],
        'CreateTime' : [0x58, ['WinFileTime', {}]],
        'LocalAddr' : [0x60, ['pointer', ['_LOCAL_ADDRESS']]],
        'InetAF' : [0x20, ['pointer', ['_INETAF']]],
        'Port' : [0x80, ['unsigned be short']],
    }],

    # Reversed from tcpip.sys!TcpStartPartitionModule
    "PARTITION_TABLE": [None, {
        "Partitions": [8, ["Array", dict(
            target="Pointer",

            count=lambda x: x.obj_profile.get_constant_object(
                "PartitionCount", "unsigned int"),

            target_args=dict(
                target="Array",
                target_args=dict(
                    count=4,
                    target="FIRST_LEVEL_DIR",
                ),
            ),
        )]],
    }],

    # ntoskrnl.exe!RtlCreateHashTable (PoolTag:HTab)
    "FIRST_LEVEL_DIR": [0x24, {
        "SizeOfSecondLevel": [0x8, ["unsigned int"]],

        "Mask": [0x10, ["unsigned int"]],

        # Reversed from ntoskrnl.exe!RtlpAllocateSecondLevelDir
        "SecondLevel": [0x20, ["Pointer", dict(
            target="Array",
            # Actual hash table (PoolTag:HTab)
            target_args=dict(
                count=lambda x: x.SizeOfSecondLevel,
                target="_LIST_ENTRY"
            )
        )]],
    }],
    "_LIST_ENTRY": basic.common_overlay["LIST_ENTRY64"],
}


tcpip_vtypes_win7_64 = {
    '_TCP_ENDPOINT': [0x320, {
        'State' : [0x68, ['Enumeration', dict(target='long',
                                              choices=TCP_STATE_ENUM)]],
        'LocalPort' : [0x6c, ['unsigned be short']],
        'RemotePort' : [0x6e, ['unsigned be short']],
        'Owner' : [0x238, ['pointer', ['_EPROCESS']]],
    }],
    '_TCP_SYN_ENDPOINT': [None, {
        'InetAF' : [0x48, ['pointer', ['_INETAF']]],
        'LocalPort' : [0x7c, ['unsigned be short']],
        'RemotePort' : [0x7e, ['unsigned be short']],
        'LocalAddr' : [0x50, ['pointer', ['_LOCAL_ADDRESS']]],
        'RemoteAddress' : [0x68, ['pointer', ['_IN_ADDR']]],
        'Owner' : [0x58, ['pointer', ['_SYN_OWNER']]],
    }],
    '_TCP_TIMEWAIT_ENDPOINT': [None, {
        'InetAF' : [0x30, ['pointer', ['_INETAF']]],
        'LocalPort' : [0x48, ['unsigned be short']],
        'RemotePort' : [0x4a, ['unsigned be short']],
        'LocalAddr' : [0x50, ['pointer', ['_LOCAL_ADDRESS']]],
        'RemoteAddress' : [0x58, ['pointer', ['_IN_ADDR']]],
    }],
    }



overlays = {
    "_ADDRESS_OBJECT": [None, {
        "Protocol": [None, ["Enumeration", dict(
            choices=protos,
            target="unsigned int")]],
    }]
}


# This is not used just yet but soon!
win7_x86_dynamic_overlays = {
    "_TCP_LISTENER": dict(
        # The Owner process.
        Owner=[
            # Attempt 1
            ["Disassembler", dict(
                start="tcpip.sys!_TcpCreateListener@8",
                length=300,
                rules=[
                    "CALL *InetGetClientProcess",
                    "MOV [EBX+$out], EAX",
                ],
                target="Pointer",
                target_args=dict(
                    target="_EPROCESS"
                ),
            )],

            # Attempt 2
            ["Disassembler", dict(
                start="tcpip.sys!_TcpCovetNetBufferList@20",
                rules=[
                    "MOV EAX, [ESI+$out]",
                    "TEST EAX, EAX",
                    "PUSH EAX",
                    "CALL DWORD *PsGetProcessId",
                ],
                target="Pointer",
                target_args=dict(
                    target="_EPROCESS"
                ),
            )]
        ],
        # Socket creation time.
        CreateTime=[
            ["Disassembler", dict(
                start="tcpip.sys!_TcpCreateListener@8",
                length=300,
                rules=[
                    "LEA EAX, [EBX+$out]",
                    "PUSH EAX",
                    "CALL DWORD *KeQuerySystemTime",
                ],
                target="WinFileTime",
            )],
        ],
    ),
}



class _TCP_LISTENER(obj.Struct):
    """Class for objects found in TcpL pools"""

    def dual_stack_sockets(self, vm=None):
        """Handle Windows dual-stack sockets"""

        # If this pointer is valid, the socket is bound to
        # a specific IP address. Otherwise, the socket is
        # listening on all IP addresses of the address family.
        local_addr = self.LocalAddr.dereference(vm=vm)

        # Switch to the correct address space.
        af_inet = self.InetAF.dereference(vm=vm)

        # Note the remote address is always INADDR_ANY or
        # INADDR6_ANY for sockets. The moment a client
        # connects to the listener, a TCP_ENDPOINT is created
        # and that structure contains the remote address.
        if local_addr:
            inaddr = local_addr.pData.dereference().dereference()
            if af_inet.AddressFamily == AF_INET:
                yield "v4", inaddr.addr4, inaddr_any
            else:
                yield "v6", inaddr.addr6, inaddr6_any
        else:
            yield "v4", inaddr_any, inaddr_any
            if af_inet.AddressFamily.v() == AF_INET6:
                yield "v6", inaddr6_any, inaddr6_any


class _TCP_ENDPOINT(_TCP_LISTENER):
    """Class for objects found in TcpE pools"""

    def _ipv4_or_ipv6(self, in_addr, vm=None):
        af_inet = self.InetAF.dereference(vm=vm)
        if af_inet.AddressFamily == AF_INET:
            return in_addr.addr4
        else:
            return in_addr.addr6

    def LocalAddress(self, vm=None):
        inaddr = self.AddrInfo.dereference(vm=vm).Local.\
            pData.dereference().dereference()

        return self._ipv4_or_ipv6(inaddr, vm=vm)

    def RemoteAddress(self, vm=None):
        inaddr = self.AddrInfo.dereference(vm=vm).\
            Remote.dereference()

        return self._ipv4_or_ipv6(inaddr, vm=vm)


class _UDP_ENDPOINT(_TCP_LISTENER):
    """Class for objects found in UdpA pools"""


class TcpipPluginMixin(object):
    """A mixin for plugins that want to use tcpip.sys profiles."""

    @classmethod
    def args(cls, parser):
        super(TcpipPluginMixin, cls).args(parser)
        parser.add_argument("--tcpip_guid", default=None,
                            help="Force this profile to be used for tcpip.")

    def __init__(self, tcpip_guid=None, **kwargs):
        super(TcpipPluginMixin, self).__init__(**kwargs)
        # For the address resolver to load this GUID.
        if tcpip_guid:
            self.session.SetCache("tcpip_guid", tcpip_guid)

        tcpip_module = self.session.address_resolver.GetModuleByName("tcpip")
        self.tcpip_profile = tcpip_module.profile
        if not self.tcpip_profile:
            raise RuntimeError("Unable to load the profile for tcpip.sys")


class Tcpip(pe_vtypes.BasicPEProfile):
    """A profile for the TCPIP driver."""

    @classmethod
    def Initialize(cls, profile):
        super(Tcpip, cls).Initialize(profile)

        # Network Object Classess for Vista, 2008, and 7 x86 and x64
        if profile.get_constant("TCP_LISTENER_ACTIVATED"):
            profile.add_classes(dict(_TCP_LISTENER=_TCP_LISTENER,
                                     _TCP_ENDPOINT=_TCP_ENDPOINT,
                                     _UDP_ENDPOINT=_UDP_ENDPOINT))

        # Switch on the kernel version. FIXME: This should be done using the
        # generate_types module.
        version = profile.session.profile.metadata("version")

        if profile.metadata("arch") == "AMD64":
            # Vista SP1.
            if version == 6.0:
                profile.add_overlay(tcpip_vtypes_vista_64)
                profile.add_overlay({
                    '_TCP_ENDPOINT': [None, {
                        'Owner' : [0x210, ['pointer', ['_EPROCESS']]],
                        }],
                    })

            # Windows 7
            elif version >= 6.1:
                profile.add_overlay(tcpip_vtypes_vista_64)
                profile.add_overlay(tcpip_vtypes_win7_64)

            # Win2k3
            elif version == 5.2:
                profile.add_overlay(tcpip_vtypes_2003_x64)

        elif profile.metadata("arch") == "I386":
            profile.add_overlay(tcpip_vtypes)

            # Win2k3
            if version == 5.2:
                profile.add_overlay(tcpip_vtypes_2003_sp1_sp2)

            # Vista
            elif version == 6.0:
                profile.add_overlay(tcpip_vtypes_vista)

            # Windows 7
            elif version >= 6.1:
                profile.add_overlay(tcpip_vtypes_vista)
                profile.add_overlay(tcpip_vtypes_7)

        # Pool tags
        profile.add_constants(dict(UDP_END_POINT_POOLTAG="UdpA",
                                   TCP_LISTENER_POOLTAG="TcpL",
                                   TCP_END_POINT_POOLTAG="TcpE"))


        profile.add_overlay(overlays)

        return profile


class TcpipHook(kb.ParameterHook):
    name = "tcpip_profile"

    def calculate(self):
        index = self.session.LoadProfile("tcpip/index")
        image_base = self.session.address_resolver.get_address_by_name("tcpip")

        for guess, _ in index.LookupIndex(image_base):
            return guess
