# Volatility
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

from volatility import obj
from volatility import utils


AF_INET = 2
AF_INET6 = 0x17

# String representations of INADDR_ANY and INADDR6_ANY
inaddr_any = utils.inet_ntop(socket.AF_INET, '\0' * 4)
inaddr6_any = utils.inet_ntop(socket.AF_INET6, '\0' * 16)


# Structures used by connections, connscan, sockets, sockscan.
# Used by x86 XP (all service packs) and x86 2003 SP0.
tcpip_vtypes = {
    '_ADDRESS_OBJECT' : [ 0x68, {
    'Next' : [ 0x0, ['pointer', ['_ADDRESS_OBJECT']]],
    'LocalIpAddress' : [ 0x2c, ['IpAddress']],
    'LocalPort' : [ 0x30, ['unsigned be short']],
    'Protocol'  : [ 0x32, ['unsigned short']],
    'Pid' : [ 0x148, ['unsigned long']],
    'CreateTime' : [ 0x158, ['WinTimeStamp', {}]],
  }],
    '_TCPT_OBJECT' : [ 0x20, {
    'Next' : [ 0x0, ['pointer', ['_TCPT_OBJECT']]],
    'RemoteIpAddress' : [ 0xc, ['IpAddress']],
    'LocalIpAddress' : [ 0x10, ['IpAddress']],
    'RemotePort' : [ 0x14, ['unsigned be short']],
    'LocalPort' : [ 0x16, ['unsigned be short']],
    'Pid' : [ 0x18, ['unsigned long']],
    }],
}

# Structures used by connections, connscan, sockets, sockscan.
# Used by x64 XP and x64 2003 (all service packs).
tcpip_vtypes_2003_x64 = {
    '_ADDRESS_OBJECT' : [ 0x250, {
    'Next' : [ 0x0, ['pointer', ['_ADDRESS_OBJECT']]],
    'LocalIpAddress' : [ 0x58, ['IpAddress']],
    'LocalPort' : [ 0x5c, ['unsigned be short']],
    'Protocol'  : [ 0x5e, ['unsigned short']],
    'Pid' : [ 0x238, ['unsigned long']],
    'CreateTime' : [ 0x248, ['WinTimeStamp', {}]],
  }],
    '_TCPT_OBJECT' : [ 0x28, {
    'Next' : [ 0x0, ['pointer', ['_TCPT_OBJECT']]],
    'RemoteIpAddress' : [ 0x14, ['IpAddress']],
    'LocalIpAddress' : [ 0x18, ['IpAddress']],
    'RemotePort' : [ 0x1c, ['unsigned be short']],
    'LocalPort' : [ 0x1e, ['unsigned be short']],
    'Pid' : [ 0x20, ['unsigned long']],
    }],
}

# Structures used by sockets and sockscan.
# Used by x86 2003 SP1 and SP2 only.
tcpip_vtypes_2003_sp1_sp2 = {
    '_ADDRESS_OBJECT' : [ 0x68, {
    'Next' : [ 0x0, ['pointer', ['_ADDRESS_OBJECT']]],
    'LocalIpAddress' : [ 0x30, ['IpAddress']],
    'LocalPort' : [ 0x34, ['unsigned be short']],
    'Protocol'  : [ 0x36, ['unsigned short']],
    'Pid' : [ 0x14C, ['unsigned long']],
    'CreateTime' : [ 0x158, ['WinTimeStamp', {}]],
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
    '_IN_ADDR' : [ None, {
    'addr4' : [ 0x0, ['IpAddress']],
    'addr6' : [ 0x0, ['Ipv6Address']],
    }],
    '_LOCAL_ADDRESS' : [ None, {
    'pData' : [ 0xC, ['pointer', ['pointer', ['_IN_ADDR']]]],
    }],
    '_TCP_LISTENER': [ 0xa8, { # TcpL
    'Owner' : [ 0x18, ['pointer', ['_EPROCESS']]],
    'CreateTime' : [ 0x20, ['WinTimeStamp', {}]],
    'LocalAddr' : [ 0x34, ['pointer', ['_LOCAL_ADDRESS']]],
    'InetAF' : [ 0x38, ['pointer', ['_INETAF']]],
    'Port' : [ 0x3E, ['unsigned be short']],
    }],
    '_TCP_ENDPOINT': [ 0x1f0, { # TcpE
    'InetAF' : [ 0xC, ['pointer', ['_INETAF']]],
    'AddrInfo' : [ 0x10, ['pointer', ['_ADDRINFO']]],
    'ListEntry': [ 0x14, ['_LIST_ENTRY']],
    'State' : [ 0x28, ['Enumeration', dict(target = 'long', choices = TCP_STATE_ENUM)]],
    'LocalPort' : [ 0x2C, ['unsigned be short']],
    'RemotePort' : [ 0x2E, ['unsigned be short']],
    'Owner' : [ 0x160, ['pointer', ['_EPROCESS']]],
    'CreateTime' : [ 0, ['WinTimeStamp', {}]],
    }],
    '_TCP_SYN_ENDPOINT': [ None, {
    'ListEntry': [ 8, ['_LIST_ENTRY']],
    'InetAF' : [ 0x18, ['pointer', ['_INETAF']]],
    'LocalPort' : [ 0x3c, ['unsigned be short']],
    'RemotePort' : [ 0x3e, ['unsigned be short']],
    'LocalAddr' : [ 0x1c, ['pointer', ['_LOCAL_ADDRESS']]],
    'RemoteAddress' : [ 0x28, ['pointer', ['_IN_ADDR']]],
    'Owner' : [ 0x20, ['pointer', ['_SYN_OWNER']]],
    'CreateTime' : [ 0, ['WinTimeStamp', {}]],
    }],
    '_SYN_OWNER': [ None, {
    'Process': [ 0x18, ['pointer', ['_EPROCESS']]],
    }],
    '_TCP_TIMEWAIT_ENDPOINT': [ None, {
    'ListEntry': [ 0x14, ['_LIST_ENTRY']],
    'InetAF' : [ 0xc, ['pointer', ['_INETAF']]],
    'LocalPort' : [ 0x1c, ['unsigned be short']],
    'RemotePort' : [ 0x1e, ['unsigned be short']],
    'LocalAddr' : [ 0x20, ['pointer', ['_LOCAL_ADDRESS']]],
    'RemoteAddress' : [ 0x24, ['pointer', ['_IN_ADDR']]],
    'CreateTime' : [ 0, ['WinTimeStamp', {}]],
    }],
    '_INETAF' : [ None, {
    'AddressFamily' : [ 0xC, ['unsigned short']],
    }],
    '_ADDRINFO' : [ None, {
    'Local' : [ 0x0, ['pointer', ['_LOCAL_ADDRESS']]],
    'Remote' : [ 0x8, ['pointer', ['_IN_ADDR']]],
    }],
    '_UDP_ENDPOINT': [ 0xa8, { # UdpA
    'Owner' : [ 0x18, ['pointer', ['_EPROCESS']]],
    'CreateTime' : [ 0x30, ['WinTimeStamp', {}]],
    'LocalAddr' : [ 0x38, ['pointer', ['_LOCAL_ADDRESS']]],
    'InetAF' : [ 0x14, ['pointer', ['_INETAF']]],
    'Port' : [ 0x48, ['unsigned be short']],
    }],
}

# Structures for netscan on x86 Windows 7 (all service packs).
tcpip_vtypes_7 = {
    '_TCP_ENDPOINT': [ 0x210, { # TcpE
    'InetAF' : [ 0xC, ['pointer', ['_INETAF']]],
    'AddrInfo' : [ 0x10, ['pointer', ['_ADDRINFO']]],
    'ListEntry': [ 0x14, ['_LIST_ENTRY']],
    'State' : [ 0x34, ['Enumeration', dict(target = 'long', choices = TCP_STATE_ENUM)]],
    'LocalPort' : [ 0x38, ['unsigned be short']],
    'RemotePort' : [ 0x3A, ['unsigned be short']],
    'Owner' : [ 0x174, ['pointer', ['_EPROCESS']]],
    'CreateTime' : [ 0, ['WinTimeStamp', {}]],
    }],
    '_TCP_SYN_ENDPOINT': [ None, {
    'ListEntry': [ 8, ['_LIST_ENTRY']],
    'InetAF' : [ 0x24, ['pointer', ['_INETAF']]],
    'LocalPort' : [ 0x48, ['unsigned be short']],
    'RemotePort' : [ 0x4a, ['unsigned be short']],
    'LocalAddr' : [ 0x28, ['pointer', ['_LOCAL_ADDRESS']]],
    'RemoteAddress' : [ 0x34, ['pointer', ['_IN_ADDR']]],
    'Owner' : [ 0x2c, ['pointer', ['_SYN_OWNER']]],
    'CreateTime' : [ 0, ['WinTimeStamp', {}]],
    }],
    '_TCP_TIMEWAIT_ENDPOINT': [ None, {
    'ListEntry': [ 0, ['_LIST_ENTRY']],
    'InetAF' : [ 0x18, ['pointer', ['_INETAF']]],
    'LocalPort' : [ 0x28, ['unsigned be short']],
    'RemotePort' : [ 0x2a, ['unsigned be short']],
    'LocalAddr' : [ 0x2c, ['pointer', ['_LOCAL_ADDRESS']]],
    'RemoteAddress' : [ 0x30, ['pointer', ['_IN_ADDR']]],
    'CreateTime' : [ 0, ['WinTimeStamp', {}]],
    }],
}

# Structures for netscan on x64 Vista SP0 and 2008 SP0
tcpip_vtypes_vista_64 = {
    '_IN_ADDR' : [ None, {
    'addr4' : [ 0x0, ['IpAddress']],
    'addr6' : [ 0x0, ['Ipv6Address']],
    }],
    '_TCP_LISTENER': [ 0x120, { # TcpL
    'Owner' : [ 0x28, ['pointer', ['_EPROCESS']]],
    'CreateTime' : [ 0x20, ['WinTimeStamp', {}]],
    'LocalAddr' : [ 0x58, ['pointer', ['_LOCAL_ADDRESS']]],
    'InetAF' : [ 0x60, ['pointer', ['_INETAF']]],
    'Port' : [ 0x6a, ['unsigned be short']],
    }],
    '_INETAF' : [ None, {
    'AddressFamily' : [ 0x14, ['unsigned short']],
    }],
    '_LOCAL_ADDRESS' : [ None, {
    'pData' : [ 0x10, ['pointer', ['pointer', ['_IN_ADDR']]]],
    }],
    '_ADDRINFO' : [ None, {
    'Local' : [ 0x0, ['pointer', ['_LOCAL_ADDRESS']]],
    'Remote' : [ 0x10, ['pointer', ['_IN_ADDR']]],
    }],
    '_TCP_ENDPOINT': [ 0x320, { # TcpE
    'InetAF' : [ 0x18, ['pointer', ['_INETAF']]],
    'AddrInfo' : [ 0x20, ['pointer', ['_ADDRINFO']]],
    'ListEntry': [ 0x28, ['_LIST_ENTRY']],
    'State' : [ 0x50, ['Enumeration', dict(target = 'long', choices = TCP_STATE_ENUM)]],
    'LocalPort' : [ 0x54, ['unsigned be short']],
    'RemotePort' : [ 0x56, ['unsigned be short']],
    'Owner' : [ 0x208, ['pointer', ['_EPROCESS']]],
    'CreateTime' : [ 0, ['WinTimeStamp', {}]],
    }],
    '_TCP_SYN_ENDPOINT': [ None, {
    'ListEntry': [ 0x10, ['_LIST_ENTRY']],
    'InetAF' : [ 0x30, ['pointer', ['_INETAF']]],
    'LocalPort' : [ 0x64, ['unsigned be short']],
    'RemotePort' : [ 0x66, ['unsigned be short']],
    'LocalAddr' : [ 0x38, ['pointer', ['_LOCAL_ADDRESS']]],
    'RemoteAddress' : [ 0x50, ['pointer', ['_IN_ADDR']]],
    'Owner' : [ 0x40, ['pointer', ['_SYN_OWNER']]],
    'CreateTime' : [ 0, ['WinTimeStamp', {}]],
    }],
    '_SYN_OWNER': [ None, {
    'Process': [ 0x28, ['pointer', ['_EPROCESS']]],
    }],
    '_TCP_TIMEWAIT_ENDPOINT': [ None, {
    'ListEntry': [ 0, ['_LIST_ENTRY']],
    'InetAF' : [ 0x18, ['pointer', ['_INETAF']]],
    'LocalPort' : [ 0x30, ['unsigned be short']],
    'RemotePort' : [ 0x32, ['unsigned be short']],
    'LocalAddr' : [ 0x38, ['pointer', ['_LOCAL_ADDRESS']]],
    'RemoteAddress' : [ 0x40, ['pointer', ['_IN_ADDR']]],
    'CreateTime' : [ 0, ['WinTimeStamp', {}]],
    }],
    '_UDP_ENDPOINT': [ 0x150, { # UdpA
    'Owner' : [ 0x28, ['pointer', ['_EPROCESS']]],
    'CreateTime' : [ 0x58, ['WinTimeStamp', {}]],
    'LocalAddr' : [ 0x60, ['pointer', ['_LOCAL_ADDRESS']]],
    'InetAF' : [ 0x20, ['pointer', ['_INETAF']]],
    'Port' : [ 0x80, ['unsigned be short']],
    }],
}


tcpip_vtypes_win7_64 = {
    '_TCP_ENDPOINT': [ 0x320, {
            'State' : [ 0x68, ['Enumeration', dict(target='long',
                                                   choices=TCP_STATE_ENUM)]],

            'LocalPort' : [ 0x6c, ['unsigned be short']],
            'RemotePort' : [ 0x6e, ['unsigned be short']],
            'Owner' : [ 0x238, ['pointer', ['_EPROCESS']]],
            }],
    '_TCP_SYN_ENDPOINT': [ None, {
            'InetAF' : [ 0x48, ['pointer', ['_INETAF']]],
            'LocalPort' : [ 0x7c, ['unsigned be short']],
            'RemotePort' : [ 0x7e, ['unsigned be short']],
            'LocalAddr' : [ 0x50, ['pointer', ['_LOCAL_ADDRESS']]],
            'RemoteAddress' : [ 0x68, ['pointer', ['_IN_ADDR']]],
            'Owner' : [ 0x58, ['pointer', ['_SYN_OWNER']]],
            }],
    '_TCP_TIMEWAIT_ENDPOINT': [ None, {
            'InetAF' : [ 0x30, ['pointer', ['_INETAF']]],
            'LocalPort' : [ 0x48, ['unsigned be short']],
            'RemotePort' : [ 0x4a, ['unsigned be short']],
            'LocalAddr' : [ 0x50, ['pointer', ['_LOCAL_ADDRESS']]],
            'RemoteAddress' : [ 0x58, ['pointer', ['_IN_ADDR']]],
            }],
    }


#--------------------------------------------------------------------------------
# object classes
#--------------------------------------------------------------------------------

class _TCP_LISTENER(obj.CType):
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


class TCPIPModifications(obj.ProfileModification):
    """A profile modification which adds structures related to TCP sockets.

    Note that most of these do not come from the PDB files, but are reversed.
    """

    @classmethod
    def modify(cls, profile):
        # Network Object Classess for Vista, 2008, and 7 x86 and x64
        if profile.metadatas("major", "minor") >= (6, 0):
            profile.add_classes(dict(_TCP_LISTENER=_TCP_LISTENER,
                                     _TCP_ENDPOINT=_TCP_ENDPOINT,
                                     _UDP_ENDPOINT=_UDP_ENDPOINT))

        if profile.metadata("memory_model") == "64bit":
            # Vista SP1.
            if (profile.metadatas("major", "minor") == (6, 0) and
                  profile.metadata("build") >= 6001):
                profile.add_overlay(tcpip_vtypes_vista_64)
                profile.add_overlay({
                        '_TCP_ENDPOINT': [ None, {
                                'Owner' : [ 0x210, ['pointer', ['_EPROCESS']]],
                                }],
                        })

            # Windows 7
            elif profile.metadatas("major", "minor") == (6, 1):
                profile.add_overlay(tcpip_vtypes_vista_64)
                profile.add_overlay(tcpip_vtypes_win7_64)

            # Win2k3
            elif profile.metadatas("major", "minor") == (5, 2):
                profile.add_overlay(tcpip_vtypes_2003_x64)

        elif profile.metadata("memory_model") == "32bit":
            profile.add_overlay(tcpip_vtypes)

            # Win2k3
            if profile.metadatas("major", "minor") == (5, 2):
                profile.add_overlay(tcpip_vtypes_2003_sp1_sp2)

            # Vista
            elif profile.metadatas("major", "minor") == (6, 0):
                profile.add_overlay(tcpip_vtypes_vista)

            elif profile.metadatas("major", "minor") == (6, 1):
                profile.add_overlay(tcpip_vtypes_7)

        # Pool tags
        profile.add_constants(UDP_END_POINT_POOLTAG="UdpA",
                              TCP_LISTENER_POOLTAG="TcpL",
                              TCP_END_POINT_POOLTAG="TcpE")

        return profile
