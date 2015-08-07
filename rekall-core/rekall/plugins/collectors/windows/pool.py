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
Collectors that scan the pool allocator.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

from rekall.entities import collector
from rekall.entities import definitions

from rekall.plugins.collectors.windows import common
from rekall.plugins.windows import common as windows_common


class ConfiguredPoolScanner(windows_common.PoolScanner):
    @classmethod
    def configure(cls, type_name, tag_name, **kwargs):
        scanner = cls(**kwargs)
        min_size = scanner.profile.get_obj_size(type_name)
        if not min_size:
            raise ValueError(min_size)

        scanner.checks = (
            ("PoolTagCheck",
             dict(tag=scanner.profile.get_constant(tag_name))),
            ("CheckPoolSize",
             dict(min_size=min_size)),
            ("CheckPoolIndex", dict(value=0)),
            ("CheckPoolType", dict(non_paged=True, free=True, paged=True)))

        return scanner


class BasePoolCollector(common.WindowsEntityCollector):
    __abstract = True

    run_cost = collector.CostEnum.HighCost
    outputs = []
    profile_name = None
    scan_kernel_vm = False
    type_name = None
    tag_name = None

    def collect(self, hint):
        if self.profile_name:
            profile = self.session.address_resolver.LoadProfileForName(
                self.profile_name)
        else:
            profile = self.session.profile

        if not profile:
            raise RuntimeError("Unable to load profile %s" % self.profile_name)

        if self.scan_kernel_vm:
            address_space = self.session.kernel_address_space
        else:
            address_space = self.session.physical_address_space

        scanner = ConfiguredPoolScanner.configure(
            type_name=self.type_name,
            tag_name=self.tag_name,
            session=self.session,
            profile=profile,
            address_space=address_space)

        for pool_obj in scanner.scan():
            pool_header_end = pool_obj.obj_offset + pool_obj.obj_size
            struct = profile.Object(type_name=self.type_name,
                                    vm=address_space,
                                    offset=pool_header_end)
            yield definitions.Struct(base=struct,
                                     type=self.type_name)


class UdpEndpointPoolCollector(BasePoolCollector):
    type_name = "_UDP_ENDPOINT"
    tag_name = "UDP_END_POINT_POOLTAG"
    profile_name = "tcpip"

    outputs = ["Struct/type=_UDP_ENDPOINT"]


class TcpListenerPoolCollector(BasePoolCollector):
    type_name = "_TCP_LISTENER"
    tag_name = "TCP_LISTENER_POOLTAG"
    profile_name = "tcpip"

    outputs = ["Struct/type=_TCP_LISTENER"]


class TcpEndpointPoolCollector(BasePoolCollector):
    type_name = "_TCP_ENDPOINT"
    tag_name = "TCP_END_POINT_POOLTAG"
    profile_name = "tcpip"

    outputs = ["Struct/type=_TCP_ENDPOINT"]
