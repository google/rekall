# Rekall Memory Forensics
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

"""This address space overlays a pagefile into the physical address space.

This essentially implements the --pagefile parameter. Note that for images taken
with winpmem there is no need to specify the pagefile specifically since it is
already detected by the Elf64CoreDump class.
"""

__author__ = "Michael Cohen <scudette@gmail.com>"

from rekall import addrspace
from rekall import config
from rekall import session


config.DeclareOption(
    "--pagefile", type="ArrayStringParser", default=[],
    help="A pagefile to load into the image.")


class PagefilePhysicalAddressSpace(addrspace.RunBasedAddressSpace):
    __image = True
    name = "pagefile"
    order = 200

    def __init__(self, **kwargs):
        super(PagefilePhysicalAddressSpace, self).__init__(**kwargs)
        pagefile_names = self.session.GetParameter("pagefile")

        self.as_assert(pagefile_names, "Pagefile not specified")
        self.as_assert(self.base.__class__ is not self.__class__)

        # Copy the base's runs to our runs and pass them through.
        for run in self.base.get_mappings():
            self.add_run(run.start, run.start, run.length, self.base)

        vaddr = self.base.end() + 0x10000

        # FIXME: Properly support multiple pagefiles.
        load_as = self.session.plugins.load_as(session=session.Session())
        for pagefile_name in pagefile_names:
            pagefile_as = load_as.GuessAddressSpace(filename=pagefile_name)

            if pagefile_as:
                self.pagefile_offset = vaddr
                vaddr += pagefile_as.end()
                self.pagefile_end = vaddr
                self.add_run(vaddr, 0, pagefile_as.end(), pagefile_as)
