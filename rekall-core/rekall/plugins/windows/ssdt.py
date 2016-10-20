# Rekall Memory Forensics
# Copyright 2014 Google Inc. All Rights Reserved.
#
# Authors:
# Michael Cohen <scudette@gmail.com>

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


# This code is loosely based on the original Volatility code, except that it is
# much simpler, since all the information we need is taken directly from the
# profile.

from rekall import utils
from rekall.plugins.windows import common


class WinSSDT(common.WindowsCommandPlugin):
    """Enumerate the SSDT."""

    name = "ssdt"

    table_header = [
        dict(name="divider", type="Divider"),
        dict(name="entry_obj", hidden=True),
        dict(name="entry", style="address"),
        dict(name="target", style="address"),
        dict(name="symbol")
    ]

    def _find_process_context(self, table_ptr, cc):
        for proc in self.session.plugins.pslist(
                proc_regex="csrss").filter_processes():

            cc.SwitchProcessContext(proc)
            table_ptr.obj_vm = self.session.GetParameter(
                "default_address_space")

            if table_ptr.is_valid():
                break

        return table_ptr

    def _render_x64_table(self, table):
        resolver = self.session.address_resolver

        for j, entry in enumerate(table):
            function_address = table.v() + (entry >> 4)
            yield dict(
                entry=j, target=function_address,
                symbol=utils.FormattedAddress(resolver, function_address))

    def _render_x86_table(self, table):
        resolver = self.session.address_resolver

        for j, function_address in enumerate(table):
            yield dict(
                entry=j, target=function_address,
                symbol=utils.FormattedAddress(resolver, function_address))

    def collect(self):
        # Directly get the SSDT.
        # http://en.wikipedia.org/wiki/System_Service_Dispatch_Table
        ssdt = self.session.address_resolver.get_constant_object(
            "nt!KeServiceDescriptorTableShadow",
            target="_SERVICE_DESCRIPTOR_TABLE")

        cc = self.session.plugins.cc()
        with cc:
            for i, descriptor in enumerate(ssdt.Descriptors):
                table_ptr = descriptor.KiServiceTable

                # Sometimes the table is not mapped. In this case we need to
                # find a process context which maps the win32k.sys driver.
                if table_ptr[0] == 0:
                    table_ptr = self._find_process_context(table_ptr, cc)

                yield dict(
                    divider="Table %s @ %#x" % (i, table_ptr[0].obj_offset))

                if self.profile.metadata("arch") == "AMD64":
                    for x in self._render_x64_table(table_ptr):
                        yield x
                else:
                    for x in self._render_x86_table(table_ptr):
                        yield x
