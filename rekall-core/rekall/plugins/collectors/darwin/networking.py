# Rekall Memory Forensics
#
# Copyright 2014 Google Inc. All Rights Reserved.
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
Collectors for sockets, interfaces, etc.
"""
__author__ = "Adam Sindelar <adamsh@google.com>"

from rekall import utils

from rekall.entities import definitions

from rekall.plugins.collectors.darwin import common
from rekall.plugins.collectors.darwin import zones


class DarwinIfnetCollector(common.DarwinEntityCollector):
    """Walks the global list of interfaces.

    The head of the list of network interfaces is a kernel global [1].
    The struct we use [2] is just the public part of the data [3]. Addresses
    are related to an interface in a N:1 relationship [4]. AF-specific data
    is a normal sockaddr struct.

    References:
      1:
      https://github.com/opensource-apple/xnu/blob/10.9/bsd/net/dlil.c#L254
      2:
      https://github.com/opensource-apple/xnu/blob/10.9/bsd/net/if_var.h#L528
      3:
      https://github.com/opensource-apple/xnu/blob/10.9/bsd/net/dlil.c#L188
      4:
      https://github.com/opensource-apple/xnu/blob/10.9/bsd/net/if_var.h#L816
    """

    outputs = ["Struct/type=ifnet"]

    def collect(self, hint):
        ifnet_head = self.profile.get_constant_object(
            "_dlil_ifnet_head",
            target="Pointer",
            target_args=dict(
                target="ifnet"))

        for ifnet in ifnet_head.walk_list("if_link.tqe_next"):
            yield [
                definitions.Struct(
                    base=ifnet,
                    type="ifnet")]


class DarwinNetworkInterfaceParser(common.DarwinEntityCollector):

    collect_args = dict(ifnets="Struct/type is 'ifnet'")
    outputs = ["NetworkInterface", "Endpoint/local=True", "OSILayer2",
               "OSILayer3"]

    def collect(self, hint, ifnets):
        for entity in ifnets:
            ifnet = entity["Struct/base"]

            yield [
                entity.identity,
                definitions.NetworkInterface(
                    name="%s%d" % (ifnet.if_name.deref(), ifnet.if_unit))]

            l2_addr = None
            l3_addrs = []
            # Parse all the addresses on the interface. There should be exactly
            # one link layer (L2) address.
            for tqe in ifnet.if_addrhead.tqh_first.walk_list(
                    "ifa_link.tqe_next"):
                family = tqe.ifa_addr.sa_family
                if family == "AF_LINK":
                    l2_addr = utils.SmartUnicode(tqe.ifa_addr.deref())
                    continue

                if family == "AF_INET":
                    l3_proto = "IPv4"
                elif family == "AF_INET6":
                    l3_proto = "IPv6"
                else:
                    l3_proto = utils.SmartUnicode(family).replace("AF_", "")

                l3_addrs.append((l3_proto, unicode(tqe.ifa_addr.deref())))

            # Yield all the endpoints as the shared L2 + each L3.
            for l3_proto, l3_addr in l3_addrs:
                endpoint_identity = self.manager.identify({
                    ("Endpoint/interface", "OSILayer3/address",
                     "OSILayer2/address"):
                    (entity.identity, l3_addr, l2_addr)})
                yield [
                    endpoint_identity,
                    definitions.Endpoint(
                        local=True,
                        interface=entity.identity),
                    definitions.OSILayer2(
                        address=l2_addr,
                        protocol="MAC"),
                    definitions.OSILayer3(
                        address=l3_addr,
                        protocol=unicode(l3_proto))]


class DarwinSocketZoneCollector(zones.DarwinZoneElementCollector):
    outputs = ["Struct/type=socket"]
    zone_name = "socket"
    type_name = "socket"

    def validate_element(self, socket):
        return socket == socket.so_rcv.sb_so


class DarwinSocketLastAccess(common.DarwinEntityCollector):
    outputs = ["Event"]
    collect_args = dict(processes="has component Process",
                        sockets="Struct/type is 'socket'")
    complete_input = True

    def collect(self, hint, processes, sockets):
        by_pid = {}
        for process in processes:
            by_pid[process["Process/pid"]] = process

        for socket in sockets:
            base_socket = socket["Struct/base"]
            process = by_pid.get(base_socket.last_pid)

            # There is no guarantee the process with last_pid is still alive.
            if not process:
                continue

            event_identity = self.manager.identify({
                ("Event/actor", "Event/action", "Event/target",
                 "Event/category"):
                (process.identity, "accessed", socket.identity, "latest")})
            yield [
                event_identity,
                definitions.Event(
                    actor=process.identity,
                    action="accessed",
                    target=socket.identity,
                    category="latest")]


class DarwinSocketParser(common.DarwinEntityCollector):
    """Searches for all memory objects that are sockets and parses them."""

    _name = "sockets"
    outputs = [
        "Connection",
        "OSILayer3",
        "OSILayer4",
        "Socket",
        "Handle",
        "Event",
        "Timestamps",
        "File/type=socket",
        "Named",
        "Struct/type=vnode"]

    collect_args = dict(sockets="Struct/type is 'socket'")

    filter_input = True

    def collect(self, hint, sockets):
        for socket in sockets:
            base_socket = socket["Struct/base"]
            family = str(base_socket.addressing_family).replace("AF_", "")

            if family in ("INET", "INET6"):
                l3_protocol = "IPv4" if family == "INET" else "IPv6"

                source_identity, source = self.prebuild(
                    components=[
                        definitions.OSILayer3(
                            address=base_socket.src_addr,
                            protocol=l3_protocol),
                        definitions.OSILayer4(
                            port=base_socket.src_port,
                            protocol=base_socket.l4_protocol,
                            state=base_socket.tcp_state)],
                    keys=("OSILayer3/address", "OSILayer4/port",
                          "OSILayer4/protocol"))

                destination_identity, destination = self.prebuild(
                    components=[
                        definitions.OSILayer3(
                            address=base_socket.dst_addr,
                            protocol=l3_protocol),
                        definitions.OSILayer4(
                            port=base_socket.dst_port,
                            protocol=base_socket.l4_protocol)],
                    keys=("OSILayer3/address", "OSILayer4/port",
                          "OSILayer4/protocol"))

                connection = [
                    socket.identity,
                    definitions.Named(name=base_socket.human_name,
                                      kind="IP Connection"),
                    definitions.Connection(protocol_family=family,
                                           source=source_identity,
                                           destination=destination_identity)]

                yield source
                yield destination
                yield connection
            elif family == "UNIX":
                if base_socket.vnode:
                    path = base_socket.vnode.full_path
                    file_identity = self.session.entities.identify({
                        "File/path": path})
                else:
                    path = None
                    file_identity = None

                yield [
                    socket.identity,
                    definitions.Named(
                        name=base_socket.human_name,
                        kind="Unix Socket"),
                    definitions.Connection(
                        protocol_family="UNIX"),
                    definitions.Socket(
                        type=base_socket.unix_type,
                        file=file_identity,
                        address="0x%x" % int(base_socket.so_pcb),
                        connected="0x%x" % int(base_socket.unp_conn))]

                # There may be a vnode here - if so, yield it.
                if path:
                    yield [
                        definitions.File(
                            path=path,
                            type="socket"),
                        definitions.Named(
                            name=path,
                            kind="Socket"),
                        definitions.Struct(
                            base=base_socket.vnode.deref(),
                            type="vnode")]
            else:
                yield [
                    socket.identity,
                    definitions.Named(
                        kind="Unknown Socket"),
                    definitions.Connection(
                        protocol_family=family)]


class UnpListCollector(common.DarwinEntityCollector):
    """Walks the global unpcb lists and returns the unix sockets.

    See here:
        github.com/opensource-apple/xnu/blob/10.9/bsd/kern/uipc_usrreq.c#L121
    """

    outputs = ["Struct/type=socket", "Named/kind=Unix Socket"]

    def collect(self, hint):
        for head_const in ["_unp_dhead", "_unp_shead"]:
            lhead = self.session.get_constant_object(
                head_const,
                target="unp_head")

            for unp in lhead.lh_first.walk_list("unp_link.le_next"):
                yield [
                    definitions.Struct(
                        base=unp.unp_socket,
                        type="socket"),
                    definitions.Named(
                        kind="Unix Socket")]
