# Rekall Memory Forensics
#
# Copyright 2012 Michael Cohen <scudette@gmail.com>
# Copyright 2013 Google Inc. All Rights Reserved.
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

"""An Address Space for processing MACH-O coredumps."""

from rekall import addrspace
from rekall.plugins.overlays.darwin import macho


class MACHOCoreDump(addrspace.RunBasedAddressSpace):
    """This AS supports MACH-O coredump files."""

    __name = "macho64"
    _md_image = True

    def __init__(self, **kwargs):
        super(MACHOCoreDump, self).__init__(**kwargs)

        self.check_file()

        # Try to parse the file now.
        macho_profile = macho.MACHO64Profile()
        self.header = macho_profile.mach_header_64(
            vm=self.base, offset=0)

        # Make sure the file is marked as MH_CORE here.
        # self.as_assert(self.header.filetype == "MH_CORE")

        for segment in self.header.segments:
            # We only map segments into memory.
            if segment.cmd == "LC_SEGMENT_64":
                self.runs.insert(
                    (segment.vmaddr, segment.fileoff, segment.filesize))

    def check_file(self):
        """Check for a valid MACH-O file."""
        self.as_assert(self.base,
                       "Must stack on another address space")

        ## Must start with the magic for macho 64.
        self.as_assert((self.base.read(0, 4) == "\xcf\xfa\xed\xfe"),
                       "Header signature invalid")

