# Volatility
# Copyright (C) 2012 Michael Cohen
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

"""This module print details information about PE files and processes.

Output is similar to objdump or pefile.
"""

__author__ = "Michael Cohen <scudette@gmail.com>"

from volatility import plugin
from volatility.plugins.overlays.windows import pe_vtypes
from volatility.plugins.windows import common


class PEInfo(plugin.Command):
    """Print information about a PE binary."""

    __name = "peinfo"

    def __init__(self, address_space=None, image_base=None, **kwargs):
        """Dump a PE binary from memory.

        Args:
          address_space: The address space which contains the PE image.
          image_base: The address of the image base (dos header).
        """
        super(PEInfo, self).__init__(**kwargs)
        self.address_space = address_space
        self.image_base = image_base

    def render(self, renderer):
        """Print information about a PE file from memory."""
        # Get our helper object to parse the PE file.
        pe_helper = pe_vtypes.PE(address_space=self.address_space,
                                 image_base=self.image_base)

        renderer.table_header([('', '<20'),
                               ('', dict(wrap=True, width=60))])
        for field in ["Machine", "TimeDateStamp", "Characteristics"]:
            renderer.table_row(field,
                               getattr(pe_helper.nt_header.FileHeader, field))

        renderer.write("\nSections:\n")
        renderer.table_header([('Perm', '4'),
                               ('Name', '<8'),
                               ('VMA',  '[addrpad]'),
                               ('Size', '[addrpad]')])

        for permission, name, virtual_address, size in pe_helper.Sections():
            renderer.table_row(permission, name, virtual_address, size)

        renderer.write("\nData Directories:\n")
        renderer.table_header([('', '<40'),
                               ('VMA',  '[addrpad]'),
                               ('Size', '[addrpad]')])

        for d in pe_helper.nt_header.OptionalHeader.DataDirectory:
            renderer.table_row(d.obj_name, d.VirtualAddress, d.Size)


        renderer.write("\nImport Directory (Original):\n")
        renderer.table_header([('Name',  '<50'),
                               ('Ord', '5')])

        for dll, name, ordinal in pe_helper.ImportDirectory():
            renderer.table_row(u"%s!%s" % (dll, name), ordinal)

        renderer.write("\nExport Directory:\n")
        renderer.table_header([('Entry Point', '[addrpad]'),
                               ('Ord', '5'),
                               ('Name',  '<50')])

        for dll, function, name, ordinal in pe_helper.ExportDirectory():
            renderer.table_row(function, ordinal, u"%s!%s" % (dll, name))




class ProcInfo(common.WinProcessFilter):
    """Dump detailed information about a running process."""

    __name = "procinfo"

    def render(self, outfd):
        for task in self.filter_processes():
            outfd.write("*" * 72 + "\n")
            outfd.write("Pid: %s %s\n" % (task.UniqueProcessId, task.ImageFileName))

            task_address_space = task.get_process_address_space()
            if not task_address_space:
                outfd.write("Peb Not mapped.\n")
                continue

            outfd.write("\nProcess Environment\n")
            # The environment is just a sentinal terminated array of strings.
            for line in task.Peb.ProcessParameters.Environment:
                outfd.write("   %s\n" % line)

            outfd.write("\nPE Infomation\n")

            # Parse the PE file of the main process's executable.
            pe = PEInfo(address_space=task_address_space,
                        image_base=task.Peb.ImageBaseAddress)

            pe.render(outfd)

            # Now parse all the modules in this executable.
