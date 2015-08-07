# Rekall Memory Forensics
#
# Copyright 2015 Google Inc. All Rights Reserved.
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
Windows networking collectors.
"""
__author__ = "Adam Sindelar <adamsh@google.com>"

from rekall.entities import definitions

from rekall.plugins.collectors.windows import common

# Python's socket.AF_INET6 is 0x1e but Microsoft defines it
# as a constant value of 0x17 in their source code. Thus we
# need Microsoft's since that's what is found in memory.
AF_INET = 2
AF_INET6 = 0x17


class WindowsUDPEndpointParser(common.WindowsEntityCollector):
    outputs = ["Endpoint", "OSILayer3", "Named/kind=UDP Endpoint",
               "OSILayer4/protocol=UDP"]
    collect_args = dict(endpoints="Struct/type == '_UDP_ENDPOINT'")

    def collect(self, hint, endpoints):
        for entity in endpoints:
            struct = entity["Struct/base"]
            af_inet = struct.InetAF.dereference(
                vm=self.session.kernel_address_space)

            if af_inet.AddressFamily == AF_INET:
                family = "INET"
            elif af_inet.AddressFamily == AF_INET6:
                family = "INET6"
            else:
                continue

            l4_port = struct.Port

            for ver, laddr, _ in struct.dual_stack_sockets(
                    vm=self.session.kernel_address_space):
                l3_protocol = "IP%s" % ver
                epoint_id = self.manager.identify({
                    ("OSILayer3/address", "OSILayer4/port",
                     "OSILayer4/protocol"):
                    (laddr, l4_port, "UDP")})

                yield [
                    epoint_id,
                    definitions.Named(
                        kind="UDP Endpoint",
                        name="%s:%s (%s)" % (laddr, l4_port, "UDP")),
                    definitions.OSILayer3(
                        address=laddr,
                        protocol=l3_protocol),
                    definitions.OSILayer4(
                        port=l4_port,
                        protocol="UDP"),
                    definitions.Endpoint(
                        addressing_family=family,
                        local=True)]
