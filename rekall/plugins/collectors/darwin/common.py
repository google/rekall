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
Darwin entity collectors - common code.
"""
__author__ = "Adam Sindelar <adamsh@google.com>"

from rekall.entities import collector
from rekall.entities import definitions


class DarwinEntityCollector(collector.EntityCollector):
    """Base class for all Darwin collectors."""

    __abstract = True

    @classmethod
    def is_active(cls, session):
        return (super(DarwinEntityCollector, cls).is_active(session) and
                session.profile.metadata("os") == "darwin")


class DarwinNetworkInterfaceCollector(DarwinEntityCollector):
    """Walks the global list of interfaces.

    The head of the list of network interfaces is a kernel global [1].
    The struct we use [2] is just the public part of the data [3]. Addresses
    are related to an interface in a N:1 relationship [4]. AF-specific data
    is a normal sockaddr struct.

    Yields:
      Network interfaces.

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

    outputs = ["NetworkInterface", "MemoryObject/type=ifnet"]

    def collect(self, hint):
        ifnet_head = self.profile.get_constant_object(
            "_dlil_ifnet_head",
            target="Pointer",
            target_args=dict(
                target="ifnet"))

        for ifnet in ifnet_head.walk_list("if_link.tqe_next"):
            yield [
                definitions.NetworkInterface(
                    name="%s%d" % (
                        ifnet.if_name.deref(),
                        ifnet.if_unit),
                    addresses=[
                        (tqe.ifa_addr.sa_family, tqe.ifa_addr.deref())
                        for tqe
                        in ifnet.if_addrhead.tqh_first.walk_list(
                            "ifa_link.tqe_next")]),
                definitions.MemoryObject(
                    base_object=ifnet,
                    type="ifnet")]
