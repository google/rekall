# Rekall Memory Forensics
# Copyright (c) 2012, Michael Cohen <scudette@gmail.com>
# Copyright (c) 2010, 2011, 2012 Michael Ligh <michael.ligh@mnin.org>
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

from rekall import addrspace
from rekall import utils

from rekall.plugins import yarascanner
from rekall.plugins.addrspaces import standard
from rekall.plugins.response import common



class FileYaraScanner(yarascanner.YaraScanMixin,
                      common.AbstractIRCommandPlugin):
    """Yara scanner which operates on files."""
    name = "file_yara"

    __args = [
        dict(name="paths", positional=True, type="Array",
             help="Paths to scan."),
    ]


    def collect(self):
        count = 0

        for path in self.plugin_args.paths:
            self.session.logging.debug("File yara scanning %s", path)
            file_info = common.FileFactory(path, session=self.session)
            run = addrspace.Run(start=0, end=file_info.st_size,
                                file_offset=0,
                                address_space=standard.FDAddressSpace(
                                    session=self.session,
                                    fhandle=file_info.open()))

            for rule, address in self.generate_hits(run):
                count += 1
                if count >= self.plugin_args.hits:
                    break

                yield (file_info,
                       rule, address,
                       utils.HexDumpedString(
                           run.address_space.read(
                               address - self.plugin_args.pre_context,
                               self.plugin_args.context +
                               self.plugin_args.pre_context)), None)
