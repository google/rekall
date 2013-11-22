# Volatility
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General
# Public License.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@author:       Michael Cohen (Based on original code by Andrew Case).
@license:      GNU General Public License 2.0
@contact:      scudette@gmail.com
"""
import logging

from volatility.plugins.linux import common


class CheckAFInfo(common.LinuxPlugin):
    """Verifies the operation function pointers of network protocols."""

    __name = "check_afinfo"

    def CreateChecks(self):
        """Builds the sequence of function checks we need to look at.

        We support multiple kernels by adding a bunch of function names which
        may not exisit on the current kernel. This is expected as the code
        simply ignores struct members which are not defined on this kernel.
        """
        # Older kernels have the operations in the structs.
        members = self.profile.file_operations().members.keys()
        if self.profile.has_type("seq_operations"):
            # Newer kernels use seq_ops struct.
            members.extend(["seq_ops.%s" % x
                            for x in self.profile.seq_operations().members])

        if self.profile.has_type("file_operations"):
            # Newer kernels use seq_ops struct.
            members.extend(["seq_fops.%s" % x
                            for x in self.profile.file_operations().members])

        return [
            dict(name="tcp",
                 constant_type="tcp_seq_afinfo",
                 global_vars=[
                    "tcp6_seq_afinfo",
                    "tcp4_seq_afinfo"
                    ],
                 members=members,
                 ),

            dict(name="udp",
                 constant_type="udp_seq_afinfo",
                 global_vars=[
                    "udplite6_seq_afinfo",
                    "udp6_seq_afinfo",
                    "udplite4_seq_afinfo",
                    "udp4_seq_afinfo"
                    ],
                 members=members,
                 ),
            ]

    def check_functions(self, checks):
        """Apply the checks to the kernel and yields the results."""
        self.module_plugin = self.session.plugins.lsmod(session=self.session)
        self.kernel_start = self.profile.get_constant("_text")
        self.kernel_end = self.profile.get_constant("_etext")

        for check in checks:
            for variable in check["global_vars"]:
                var_ptr = self.profile.get_constant_object(
                    variable, target=check["constant_type"],
                    vm=self.kernel_address_space)

                for member in check["members"]:
                    ptr = var_ptr.m(member)
                    if not ptr:
                        continue

                    # This is really a function pointer.
                    func = ptr.dereference_as(target="Function",
                                              target_args=dict(name=member))

                    # Check if the function is pointing inside the kernel:
                    if func > self.kernel_start and func < self.kernel_end:
                        yield variable, member, func, "Kernel"
                        continue

                    # Check if the symbol is pointing into a module.
                    module = self.module_plugin.find_module(func.obj_offset)
                    if module:
                        yield variable, member, func, module.name
                        continue

                    yield variable, member, func, "Unknown"

    def render(self, renderer):
        renderer.table_header([("Constant Name", "symbol", "30"),
                               ("Member", "member", "30"),
                               ("Address", "address", "[addrpad]"),
                               ("Module", "module", "<20")])

        checks = self.CreateChecks()
        for variable, member, func, location in self.check_functions(checks):
            # Point out suspicious constants.
            highlight="important" if location=="Unknown" else None

            renderer.table_row(variable, member, func, location,
                               highlight=highlight)

