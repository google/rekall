# Volatility
#
# Authors:
# Mike Auty <mike.auty@gmail.com>
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

#pylint: disable-msg=C0111

from volatility.plugins.windows import common


class Modules(common.KDBGMixin, common.AbstractWindowsCommandPlugin):
    """Print list of loaded modules."""

    __name = "modules"

    def __init__(self, **kwargs):
        """List kernel modules by walking the PsLoadedModuleList."""
        super(Modules, self).__init__(**kwargs)

    def lsmod(self):
        """ A Generator for modules (uses _KPCR symbols) """
        ## Try to iterate over the process list in PsActiveProcessHead
        ## (its really a pointer to a _LIST_ENTRY)
        PsLoadedModuleList = self.kdbg.PsLoadedModuleList.dereference_as(
            "_LIST_ENTRY", vm=self.kernel_address_space)

        for l in PsLoadedModuleList.list_of_type("_LDR_DATA_TABLE_ENTRY",
                                                 "InLoadOrderLinks"):
            yield l


    def render(self, outfd):
        outfd.write("Offset(V)  Offset(P)  {0:50} {1:12} {2:8} {3}\n".format(
                'File', 'Base', 'Size', 'Name'))

        for module in self.lsmod():
            offset = module.obj_offset
            outfd.write("{0:#010x} {1:#10x} {2:50} {3:#012x} {4:#08x} {5}\n".format(
                    offset, module.obj_vm.vtop(offset),
                    module.FullDllName,
                    module.DllBase,
                    module.SizeOfImage,
                    module.BaseDllName))
