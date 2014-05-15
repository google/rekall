#!/usr/bin/python

# Rekall Memory Forensics
# Copyright (C) 2014 Michael Cohen <scudette@gmail.com>
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
"""This module discovers the kernel base address.

The profile provides kernel addresses relative to the kernel base address. This
varies each time, so we need a way to locate the kernel base address in the
kernel address space.
"""

__author__ = "Michael Cohen <scudette@google.com>"
import logging

from rekall import obj
from rekall import kb
from rekall import scan
from rekall.plugins.windows import common
from rekall.plugins.overlays.windows import pe_vtypes


class ExportScanner(scan.BaseScanner):
    # We search for the name of a section present in the PE header.
    checks = [("MultiStringFinderCheck", dict(needles=[
                    "INITKDBG", "MISYSPTE", "PAGEKD"]))]



class KernelBaseHook(kb.ParameterHook):
    """Finds the kernel base address."""

    name = "kernel_base"

    def calculate(self):
        address_space = self.session.kernel_address_space
        scanner = ExportScanner(session=self.session,
                                address_space=address_space)

        # The kernel image is always loaded in the same range called the
        # "Initial Loader Mappings". Narrowing the possible range makes scanning
        # much faster. (See http://www.codemachine.com/article_x64kvas.html)
        if self.session.profile.metadata("arch") == "AMD64":
            kernel_boundary = 0xFFFFF80000000000
        else:
            kernel_boundary = 0x80000000

        kernel_boundary = obj.Pointer.integer_to_address(kernel_boundary)

        for hit in scanner.scan(offset=kernel_boundary, maxlen=2**64):

            # Search backwards for an MZ signature on the page boundary.
            page = hit & 0xFFFFFFFFFFFFF000
            for _ in range(10):
                if address_space.read(page, 2) == "MZ":
                    helper = pe_vtypes.PE(
                        address_space=address_space,
                        session=self.session, image_base=page)

                    if str(helper.RSDS.Filename) in common.KERNEL_NAMES:
                        logging.info("Detected kernel base at 0x%X", page)
                        return page
                else:
                    page -= 0x1000
