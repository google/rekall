# Rekall Memory Forensics
#
# Copyright 2015 Google Inc. All Rights Reserved.

# Authors:
# Michael Cohen <scudette@google.com>
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

"""This is an address space for the Lime file format.

Note that Lime is an ad-hoc file format produced by the Lime Linux memory
acquisition tool (https://github.com/504ensicsLabs/LiME). The format does not
really offer any advantages over the standard ELF core dump format and should
therefore be avoided. This address space simply allows Rekall to read images
produced by Lime in case you have such an image about.
"""

from rekall import addrspace
from rekall.plugins.overlays import basic


class LimeProfile(basic.ProfileLP64, basic.BasicClasses):
    """A profile for Lime files."""

    def __init__(self, **kwargs):
        super(LimeProfile, self).__init__(**kwargs)
        self.add_overlay({
            'lime_header': [0x20, {
                'magic': [0x0, ['String', dict(length=4)]],
                'version': [0x4, ['unsigned int']],

                # These are virtual addresses for the start and end addresses of
                # this segment. Note that this is an inclusive range (i.e. end
                # address is also valid).
                'start': [0x8, ['unsigned long long']],
                'end': [0x10, ['unsigned long long']],

                # The size of this section is given by subtracting the virtual
                # address of the last byte from the virtual address of the
                # beginning and then adding 1, finally we add the size of the
                # header... Wow.
                'size': lambda x: x.end - x.start + 1,

                # The next section in the file follows this header immediately.
                'next': lambda x: x.cast(
                    "lime_header",
                    offset=x.obj_offset + x.size + x.obj_size),
            }]
        })


class LimeAddressSpace(addrspace.RunBasedAddressSpace):
    """An Address Space to read from lime images."""

    name = "lime"
    __image = True

    order = 50

    def __init__(self, **kwargs):
        super(LimeAddressSpace, self).__init__(**kwargs)
        self.as_assert(self.base, "Must be layered on another address space.")
        self.as_assert(self.base.read(0, 4) == b"EMiL",
                       "Invalid Lime header signature")

        header = LimeProfile(session=self.session).lime_header(vm=self.base)
        while header.magic == "EMiL":
            self.add_run(header.start, header.obj_end, header.size)
            header = header.next

    def vtop(self, addr):
        """I have no idea why this is needed.

        This hack is also present in the Volatility address space without
        suitable explanation, so we just blindly add it here.
        """
        smallest_address = self.runs.get_next_range_start(-1)

        if addr < smallest_address:
            addr = smallest_address + addr

        return super(LimeAddressSpace, self).vtop(addr)

    def read(self, addr, length):
        smallest_address = self.runs.get_next_range_start(-1)
        if addr > 0 and addr < smallest_address:
            addr = smallest_address + addr

        return super(LimeAddressSpace, self).read(addr, length)
