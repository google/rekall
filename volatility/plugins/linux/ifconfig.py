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

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0 or later
@contact:      atcuno@gmail.com
@organization: Digital Forensics Solutions
"""
import logging

from volatility.plugins.linux import common


class Ifconfig(common.AbstractLinuxCommandPlugin):
    '''Gathers active interfaces.'''

    __name = "ifconfig"

    def enumerate_devices(self):
        """A generator over devices.

        Yields:
          a tuple of (network_dev, interface_dev) object.
        """
        # newer kernels
        if self.profile.get_constant("net_namespace_list"):
            return self.get_devs_namespace()

        elif self.profile.get_constant("dev_base"):
            return self.get_devs_base()

        else:
            logging.error("Dont know how to ifconfig this kernel.")
            return []

    def get_devs_base(self):
        net_device_ptr = self.profile.Object(
            "Pointer",
            offset=self.profile.get_constant("dev_base"),
            vm=self.kernel_address_space)

        net_device = self.profile.Object(
            "net_device",
            offset=net_device_ptr,
            vm=self.kernel_address_space)

        for net_dev in common.walk_internal_list("net_device", "next", net_device.v(), self.addr_space):

            in_dev = obj.Object("in_device", offset = net_dev.ip_ptr, vm = self.addr_space)

            yield net_dev, in_dev

    def get_devs_namespace(self):
        nslist_addr = self.profile.get_constant("net_namespace_list")
        nethead = self.profile.Object("list_head", offset = nslist_addr,
                                      vm = self.kernel_address_space)

        # walk each network namespace
        # http://www.linuxquestions.org/questions/linux-kernel-70/accessing-ip-address-from-kernel-ver-2-6-31-13-module-815578/
        for net in nethead.list_of_type("net", "list"):
            # walk each device in the current namespace
            for net_dev in net.dev_base_head.list_of_type("net_device", "dev_list"):
                in_dev = self.profile.Object(
                    "in_device", offset = net_dev.ip_ptr, vm = self.kernel_address_space)

                yield net_dev, in_dev

    def render(self, outfd):
        for net_dev, in_dev in self.enumerate_devices():
            if in_dev.ifa_list:
                # This is actually an IpAddress field.
                ip = in_dev.ifa_list.ifa_address.cast("IpAddress")
            else:
                # for interfaces w/o an ip address (dummy/bond)
                ip = "0.0.0.0"

            if self.profile.obj_has_member("net_device", "perm_addr"):
                hwaddr = net_dev.perm_addr
            else:
                hwaddr = net_dev.dev_addr

            mac_addr = ":".join(["%.02x" % x for x in hwaddr][:6])

            outfd.write("{0:8s} {1:16s} {2:32s}\n".format(
                    net_dev.name, ip, mac_addr))

