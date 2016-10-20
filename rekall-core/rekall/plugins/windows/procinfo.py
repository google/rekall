# Rekall Memory Forensics
# Copyright (C) 2012 Michael Cohen
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

"""This module print details information about PE files and processes.

Output is similar to objdump or pefile.
"""

__author__ = "Michael Cohen <scudette@gmail.com>"

from rekall import plugin
from rekall import testlib

from rekall.plugins.overlays.windows import pe_vtypes
from rekall.plugins.windows import common


class PEInfo(plugin.TypedProfileCommand, plugin.Command):
    """Print information about a PE binary."""

    __name = "peinfo"

    __args = [
        dict(name="image_base", type="SymbolAddress", positional=True,
             help="The base of the image."),

        dict(name="executable", positional=True, required=False,
             help="If provided we create an address space "
             "from this file."),

        dict(name="address_space", default=None,
             help="The address space to use.")
    ]

    def __init__(self, *args, **kwargs):
        """Dump a PE binary from memory.

        Status is shown for each exported function:

          - M: The function is mapped into memory.

        Args:
          image_base: The address of the image base (dos header). Can be a
            module name.

          address_space: The address space which contains the PE image. Can be
             specified as "K" or "P".

          filename: If provided we create an address space from this file.
        """
        super(PEInfo, self).__init__(*args, **kwargs)
        if (self.plugin_args.executable is None and
                self.plugin_args.address_space is None):
            # Resolve the correct address space. This allows the address space
            # to be specified from the command line (e.g. "P")
            load_as = self.session.plugins.load_as(session=self.session)
            self.plugin_args.address_space = load_as.ResolveAddressSpace(
                self.plugin_args.address_space)

        if self.plugin_args.image_base is None:
            self.plugin_args.image_base = self.session.GetParameter(
                "default_image_base", 0)

        self.pe_helper = pe_vtypes.PE(
            address_space=self.plugin_args.address_space, session=self.session,
            filename=self.plugin_args.executable,
            image_base=self.plugin_args.image_base)

        self.disassembler = self.session.plugins.dis(
            address_space=self.pe_helper.vm,
            session=self.session, length=4)

    def render(self, renderer):
        """Print information about a PE file from memory."""
        # Get our helper object to parse the PE file.
        renderer.table_header([('Attribute', 'attribute', '<30'),
                               ('Value', 'value', '60')])

        for field in ["Machine", "TimeDateStamp", "Characteristics"]:
            renderer.table_row(
                field,
                getattr(self.pe_helper.nt_header.FileHeader, field))

        renderer.table_row("GUID/Age", self.pe_helper.RSDS.GUID_AGE)
        renderer.table_row("PDB", self.pe_helper.RSDS.Filename)

        for field in ["MajorOperatingSystemVersion",
                      "MinorOperatingSystemVersion",
                      "MajorImageVersion",
                      "MinorImageVersion",
                      "MajorSubsystemVersion",
                      "MinorSubsystemVersion"]:
            renderer.table_row(
                field,
                getattr(self.pe_helper.nt_header.OptionalHeader, field))

        renderer.format(
            "\nSections (Relative to {0:addrpad}):\n",
            self.pe_helper.image_base)

        renderer.table_header([('Perm', 'perm', '4'),
                               ('Name', 'name', '<8'),
                               ('Raw Off', 'raw', '[addrpad]'),
                               ('VMA', 'vma', '[addrpad]'),
                               ('Size', 'size', '[addrpad]')])

        for section in self.pe_helper.nt_header.Sections:
            renderer.table_row(section.execution_flags, section.Name,
                               section.PointerToRawData,
                               section.VirtualAddress,
                               section.SizeOfRawData)

        renderer.format("\nData Directories:\n")
        renderer.table_header([('', 'name', '<40'),
                               ('VMA', 'vma', '[addrpad]'),
                               ('Size', 'size', '[addrpad]')])

        for d in self.pe_helper.nt_header.OptionalHeader.DataDirectory:
            renderer.table_row(d.obj_name, d.VirtualAddress, d.Size)


        # Export/Import directory only if verbosity is higher than 1.
        if self.plugin_args.verbosity >= 1:
            renderer.format("\nImport Directory (Original):\n")
            renderer.table_header([('Name', 'name', '<50'),
                                   ('Mapped Function', 'function', '60'),
                                   ('Ord', 'ord', '5')])

            resolver = self.session.address_resolver
            # Merge the results from both the Import table and the
            # IAT. Sometimes the original Import Table is no longer mapped into
            # memory (since its usually only used by the loader in order to
            # build the IAT). In this case we can show something sensible using
            # the address resolver.
            for (dll, name, ordinal), (_, func, _) in zip(
                    self.pe_helper.ImportDirectory(),
                    self.pe_helper.IAT()):
                renderer.table_row(
                    u"%s!%s" % (dll, name or ""),
                    resolver.format_address(func.v()),
                    ordinal)

            if self.plugin_args.verbosity >= 2:
                renderer.format("\nImport Address Table:\n")
                renderer.table_header(
                    [('Name', 'name', '<20'),
                     ('Address', 'address', '[addrpad]'),
                     ('Disassembly', 'disassembly', '30')])

                for name, function, ordinal in self.pe_helper.IAT():
                    disassembly = []

                    for x in self.disassembler.disassemble(function):
                        disassembly.append(x[-1].strip())

                    renderer.table_row(name, function, "\n".join(disassembly))

            renderer.format("\nExport Directory:\n")
            renderer.table_header([('Entry', 'entry', '[addrpad]'),
                                   ('Stat', 'status', '4'),
                                   ('Ord', 'ord', '5'),
                                   ('Name', 'name', '')])

            resolver = self.session.address_resolver

            for _ in self.pe_helper.ExportDirectory():
                dll, function, name, ordinal = _
                status = 'M' if function.dereference() else "-"

                # Resolve the exported function through the symbol resolver.
                symbol_name = resolver.format_address(function)
                if symbol_name:
                    symbol_name = u"%s!%s (%s)" % (
                        dll, name or "", ", ".join(symbol_name))
                else:
                    symbol_name = u"%s!%s" % (dll, name or "")

                renderer.table_row(
                    function,
                    status,
                    ordinal,
                    symbol_name)

        renderer.format("Version Information:\n")
        renderer.table_header([('key', 'key', '<20'),
                               ('value', 'value', '')])

        for k, v in self.pe_helper.VersionInformation():
            renderer.table_row(k, v)


class TestPEInfo(testlib.SimpleTestCase):
    PARAMETERS = dict(
        commandline="peinfo nt"
        )



class ProcInfo(common.WinProcessFilter):
    """Dump detailed information about a running process."""

    __name = "procinfo"

    def render(self, renderer):
        for task in self.filter_processes():
            renderer.section()
            renderer.format("Pid: {0} {1}\n",
                            task.UniqueProcessId, task.ImageFileName)

            task_address_space = task.get_process_address_space()
            if not task_address_space:
                renderer.format("Peb Not mapped.\n")
                continue

            renderer.format("\nProcess Environment\n")
            # The environment is just a sentinel terminated array of strings.
            for line in task.Peb.ProcessParameters.Environment:
                renderer.format("   {0}\n", line)

            renderer.format("\nPE Infomation\n")
            cc = self.session.plugins.cc()
            with cc:
                cc.SwitchProcessContext(task)

                # Parse the PE file of the main process's executable.
                pe = PEInfo(session=self.session,
                            image_base=task.Peb.ImageBaseAddress)

                pe.render(renderer)


class TestProcInfo(testlib.SimpleTestCase):
    PARAMETERS = dict(
        commandline="procinfo %(pids)s"
        )
