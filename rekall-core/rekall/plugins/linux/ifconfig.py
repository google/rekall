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

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0 or later
@contact:      atcuno@gmail.com
@organization: Digital Forensics Solutions
"""
import itertools

from rekall.plugins.linux import common


class Ifconfig(common.LinuxPlugin):
    '''Gathers active interfaces.'''

    __name = "ifconfig"

    table_header = [
        dict(name="interface", width=16),
        dict(name="ipv4", width=20),
        dict(name="MAC", width=18),
        dict(name="flags", width=20)
    ]


    def enumerate_devices(self):
        """A generator over devices.

        Yields:
          a tuple of (name, ip_addr, mac_addr, promisc).
        """
        return itertools.chain(self.get_devs_namespace(),
                               self.get_devs_base())

    def get_devs_base(self):
        net_device = self.profile.get_constant_object(
            "dev_base", target="net_device", vm=self.kernel_address_space)

        for net_dev in net_device.walk_list("next"):
            yield net_dev

    def gather_net_dev_info(self, net_dev):
        mac_addr = net_dev.mac_addr

        for dev in net_dev.ip_ptr.ifa_list.walk_list("ifa_next"):
            yield dev.ifa_label, dev.ifa_address, mac_addr, net_dev.flags

    def get_devs_namespace(self):
        nethead = self.profile.get_constant_object(
            "net_namespace_list", target="list_head",
            vm=self.kernel_address_space)

        for net in nethead.list_of_type("net", "list"):
            for net_dev in net.dev_base_head.list_of_type("net_device",
                                                          "dev_list"):
                yield net_dev

    def collect(self):
        for net_dev in self.enumerate_devices():
            for name, ipv4, mac, flags in self.gather_net_dev_info(net_dev):
                yield dict(interface=name,
                           ipv4=ipv4,
                           MAC=mac,
                           flags=flags)
