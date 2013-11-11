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

from volatility.plugins.linux import common

class Lsmod(common.AbstractLinuxCommandPlugin):
    '''Gathers loaded kernel modules.'''
    __name = "lsmod"


    def get_module_list(self):
        modules = self.profile.Object(
            "list_head", offset = self.profile.get_constant("modules"),
            vm=self.kernel_address_space)

        # walk the modules list
        for module in modules.list_of_type("module", "list"):
            yield module

    def render(self, outfd):
        outfd.write("{0:12} {1:12} {2:12}\n".format(
                'Virtual', 'Physical', 'Name'))

        for module in self.get_module_list():
            outfd.write("0x{0:12X} 0x{1:12X} {2:12}\n".format(
                    module.obj_offset,
                    module.obj_vm.vtop(module.obj_offset),
                    module.name))
