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
"""Miscelaneous information gathering plugins."""

__author__ = "Michael Cohen <scudette@google.com>"


from rekall.plugins import core
from rekall.plugins.linux import common

class LinuxSetProcessContext(core.SetProcessContextMixin,
                             common.LinProcessFilter):
    """A cc plugin for windows."""


class LinVtoP(core.VtoPMixin, common.LinProcessFilter):
    """Describe virtual to physical translation on ARM platforms."""

    def render_address(self, renderer, vaddr):
        renderer.section(name="{0:#08x}".format(vaddr))
        self.address_space = self.session.GetParameter("default_address_space")

        renderer.format("Virtual {0:addrpad} DTB {1:addr}\n",
                        vaddr, self.address_space.dtb)

        for name, value, address in self.address_space.describe_vtop(vaddr):
            if address:
                # Properly format physical addresses.
                renderer.format(
                    "{0}@ {1} = {2:addr}\n",
                    name,
                    self.physical_address_space.describe(address),
                    value or 0)
            elif value:
                renderer.format("{0} {1}\n",
                                name,
                                self.physical_address_space.describe(value))
            else:
                renderer.format("{0}\n", name)

        # The below re-does all the analysis using the address space. It should
        # agree!
        physical_address = self.address_space.vtop(vaddr)
        if physical_address is None:
            renderer.format("Physical Address Invalid\n")
        else:
            renderer.format(
                "Physical Address {0}\n",
                self.physical_address_space.describe(physical_address))
