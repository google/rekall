# Rekall Memory Forensics
#
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Authors:
# Michael Hale Ligh <michael.hale@gmail.com>
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

# pylint: disable=protected-access

from rekall.plugins.windows import common
from rekall.plugins.overlays.windows import tcpip_vtypes

# Python's socket.AF_INET6 is 0x1e but Microsoft defines it
# as a constant value of 0x17 in their source code. Thus we
# need Microsoft's since that's what is found in memory.
AF_INET = 2
AF_INET6 = 0x17

class PoolScanUdpEndpoint(common.PoolScanner):
    """PoolScanner for Udp Endpoints"""

    def __init__(self, **kwargs):
        super(PoolScanUdpEndpoint, self).__init__(**kwargs)
        min_size = self.profile.get_obj_size("_UDP_ENDPOINT")
        if not min_size:
            raise RuntimeError(repr(min_size))

        self.checks = [
            ('PoolTagCheck', dict(
                tag=self.profile.get_constant("UDP_END_POINT_POOLTAG"))),

            ('CheckPoolSize', dict(min_size=min_size)),

            ('CheckPoolType', dict(non_paged=True, free=True, paged=True)),

            ('CheckPoolIndex', dict(value=0)),
            ]


class PoolScanTcpListener(common.PoolScanner):
    """PoolScanner for Tcp Listeners"""

    def __init__(self, **kwargs):
        super(PoolScanTcpListener, self).__init__(**kwargs)
        min_size = self.profile.get_obj_size("_TCP_LISTENER")
        if not min_size:
            raise RuntimeError(repr(min_size))

        self.checks = [
            ('PoolTagCheck', dict(
                tag=self.profile.get_constant("TCP_LISTENER_POOLTAG"))),

            ('CheckPoolSize', dict(min_size=min_size)),

            ('CheckPoolType', dict(non_paged=True, free=True, paged=True)),

            ('CheckPoolIndex', dict(value=0)),
            ]


class PoolScanTcpEndpoint(common.PoolScanner):
    """PoolScanner for TCP Endpoints"""

    def __init__(self, **kwargs):
        super(PoolScanTcpEndpoint, self).__init__(**kwargs)
        min_size = self.profile.get_obj_size("_TCP_ENDPOINT")
        if not min_size:
            raise RuntimeError(repr(min_size))

        self.checks = [
            ('PoolTagCheck', dict(
                tag=self.profile.get_constant("TCP_END_POINT_POOLTAG"))),

            ('CheckPoolSize', dict(min_size=min_size)),

            ('CheckPoolType', dict(non_paged=True, free=True, paged=True)),

            ('CheckPoolIndex', dict(value=0)),
            ]


class Netscan(tcpip_vtypes.TcpipPluginMixin,
              common.PoolScannerPlugin):
    """Scan a Vista, 2008 or Windows 7 image for connections and sockets"""

    __name = "netscan"

    @classmethod
    def is_active(cls, session):
        # This plugin works with the _TCP_ENDPOINT interfaces.
        return (super(Netscan, cls).is_active(session) and
                session.profile.has_type('_TCP_ENDPOINT'))

    def generate_hits(self):
        scanner = PoolScanTcpListener(
            profile=self.profile, session=self.session,
            address_space=self.address_space)

        for pool_obj in scanner.scan():
            pool_header_end = pool_obj.obj_offset + pool_obj.size()
            tcpentry = self.profile._TCP_LISTENER(
                vm=self.address_space, offset=pool_header_end)

            # Only accept IPv4 or IPv6
            af_inet = tcpentry.InetAF.dereference(vm=self.kernel_address_space)
            if af_inet.AddressFamily not in (AF_INET, AF_INET6):
                continue

            # For TcpL, the state is always listening and the remote port is
            # zero
            for ver, laddr, raddr in tcpentry.dual_stack_sockets(
                vm=self.kernel_address_space):
                yield (tcpentry, "TCP" + ver, laddr,
                       tcpentry.Port, raddr, 0, "LISTENING")

        # Scan for TCP endpoints also known as connections
        scanner = PoolScanTcpEndpoint(
            profile=self.profile, session=self.session,
            address_space=self.address_space)

        for pool_obj in scanner.scan():
            pool_header_end = pool_obj.obj_offset + pool_obj.size()
            tcpentry = self.profile._TCP_ENDPOINT(
                vm=self.address_space, offset=pool_header_end)

            af_inet = tcpentry.InetAF.dereference(vm=self.kernel_address_space)
            if af_inet.AddressFamily == AF_INET:
                proto = "TCPv4"
            elif af_inet.AddressFamily == AF_INET6:
                proto = "TCPv6"
            else:
                continue

            owner = tcpentry.Owner.dereference(vm=self.kernel_address_space)
            local_addr = tcpentry.LocalAddress(vm=self.kernel_address_space)
            remote_addr = tcpentry.RemoteAddress(vm=self.kernel_address_space)

            # These are our sanity checks
            if tcpentry.State.v() not in tcpip_vtypes.TCP_STATE_ENUM:
                continue

            if (not owner or owner.UniqueProcessId == 0 or
                owner.UniqueProcessId > 65535) and not local_addr:
                continue

            yield (tcpentry, proto, local_addr, tcpentry.LocalPort,
                   remote_addr, tcpentry.RemotePort, tcpentry.State)

        # Scan for UDP endpoints
        scanner = PoolScanUdpEndpoint(
            profile=self.profile, session=self.session,
            address_space=self.address_space)

        for pool_obj in scanner.scan():
            pool_header_end = pool_obj.obj_offset + pool_obj.size()
            udpentry = self.profile._UDP_ENDPOINT(
                vm=self.address_space, offset=pool_header_end)

            af_inet = udpentry.InetAF.dereference(vm=self.kernel_address_space)

            # Only accept IPv4 or IPv6
            if af_inet.AddressFamily not in (AF_INET, AF_INET6):
                continue

            # For UdpA, the state is always blank and the remote end is
            # asterisks
            for ver, laddr, _ in udpentry.dual_stack_sockets(
                vm=self.kernel_address_space):
                yield (udpentry, "UDP" + ver, laddr, udpentry.Port,
                       "*", "*", "")

    def render(self, renderer):
        renderer.table_header([("Offset(P)", "offset", "[addrpad]"),
                               ("Proto", "protocol", "<8"),
                               ("Local Address", "local_addr", "<20"),
                               ("Remote Address", "remote_addr", "<20"),
                               ("State", "state", "<16"),
                               ("Pid", "pid", ">5"),
                               ("Owner", "owner", "<14"),
                               ("Created", "created", "<7")])

        for (net_object, proto, laddr, lport, raddr, rport,
             state) in self.generate_hits():
            lendpoint = "{0}:{1}".format(laddr, lport)
            rendpoint = "{0}:{1}".format(raddr, rport)

            owner = net_object.Owner.dereference(vm=self.kernel_address_space)

            renderer.table_row(
                net_object.obj_offset, proto, lendpoint,
                rendpoint, state,
                owner.UniqueProcessId,
                owner.ImageFileName,
                net_object.CreateTime)
