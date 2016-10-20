# Rekall Memory Forensics
#
# This file is part of Rekall Memory Forensics.
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Rekall Memory Forensics is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General Public
# License.
#
# Rekall Memory Forensics is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# Rekall Memory Forensics.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@author:       Michael Cohen (Based on original code by Andrew Case).
@license:      GNU General Public License 2.0
@contact:      scudette@gmail.com
"""
from rekall.plugins.linux import common


class CheckAFInfo(common.LinuxPlugin):
    """Verifies the operation function pointers of network protocols."""

    __name = "check_afinfo"

    table_header = [
        dict(name="symbol", width=30),
        dict(name="member", width=30),
        dict(name="address", style="address"),
        dict(name="module")
    ]

    def CreateChecks(self):
        """Builds the sequence of function checks we need to look at.

        We support multiple kernels by adding a bunch of function names which
        may not exisit on the current kernel. This is expected as the code
        simply ignores struct members which are not defined on this kernel.
        """
        # Older kernels have the operations in the structs.
        members = sorted(self.profile.file_operations().members.keys())
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

    def check_members(self, struct, members):
        """Yields struct members which are not known to exist in any module."""
        for member in members:
            ptr = struct.m(member)
            if not ptr:
                continue

            # This is really a function pointer.
            func = ptr.dereference_as(target="Function",
                                      target_args=dict(name=member))

            yield member, func

    def check_functions(self, checks):
        """Apply the checks to the kernel and yields the results."""
        for check in checks:
            for variable in check["global_vars"]:
                var_ptr = self.profile.get_constant_object(
                    variable, target=check["constant_type"],
                    vm=self.kernel_address_space)

                for member, func in self.check_members(
                        var_ptr, check["members"]):
                    yield variable, member, func

    def collect(self):
        checks = self.CreateChecks()
        for variable, member, func in self.check_functions(checks):
            location = ", ".join(
                self.session.address_resolver.format_address(
                    func.obj_offset))

            # Point out suspicious constants.
            highlight = None if location else "important"

            yield dict(symbol=variable, member=member, address=func,
                       module=location, highlight=highlight)
