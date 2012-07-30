# Volatility
#
# Based on the source code from
# Volatools Basic
# Copyright (C) 2007 Komoku, Inc.
#
# Authors:
# Michael Cohen <scudette@gmail.com>
# Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
# Mike Auty <mike.auty@gmail.com>
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
# The source code in this file was inspired by the excellent work of
# Brendan Dolan-Gavitt. Background information can be found in
# the following reference:
# "The VAD Tree: A Process-Eye View of Physical Memory," Brendan Dolan-Gavitt

import os.path
import sys

from volatility import plugin
from volatility import scan
from volatility.plugins.windows import common


class VADInfo(common.WinProcessFilter):
    """Dump the VAD info"""

    __name = "vadinfo"

    def render(self, renderer):
        for task in self.filter_processes():
            renderer.section()
            renderer.write("Pid: {0:6}\n".format(task.UniqueProcessId))

            count = 0
            for count, vad in enumerate(task.RealVadRoot.traverse()):
                try:
                    self.write_vad_short(renderer, vad)
                except AttributeError: pass
                try:
                    self.write_vad_control(renderer, vad)
                except AttributeError: pass
                try:
                    self.write_vad_ext(renderer, vad)
                except AttributeError: pass

                renderer.write("\n")

            self.session.report_progress("Pid %s: %s Vads" % (
                    task.UniqueProcessId, count))

    def write_vad_short(self, renderer, vad):
        """Renders a text version of a Short Vad"""
        renderer.table_header([("VAD node @", "offset", ""),
                               ("address","address", "[addrpad]"),
                               ("Start","Start", "5"),
                               ("startaddr","startaddr", "[addrpad]"),
                               ("End","End", "3"),
                               ("endaddr","endaddr", "[addrpad]"),
                               ("Tag","Tag", "3"),
                               ("tagval","tagval", ""),
                               ], suppress_headers=True)
        renderer.table_row("VAD node @",
                           vad.obj_offset,
                           "Start",
                           vad.Start,
                           "End",
                           vad.End,
                           "Tag",
                           vad.Tag)

        renderer.write("Flags: {0}\n".format(str(vad.u.VadFlags)))

        # although the numeric value of Protection is printed above with VadFlags,
        # let's show the user a human-readable translation of the protection
        renderer.write("Protection: {0}\n".format(vad.u.VadFlags.ProtectionEnum))

        # translate the vad type if its available (> XP)
        if vad.u.VadFlags.m("VadType"):
            renderer.write("Vad Type: {0}\n".format(vad.u.VadFlags.VadTypeEnum))

    def write_vad_control(self, renderer, vad):
        """Renders a text version of a (non-short) Vad's control information"""
        # even if the ControlArea is not NULL, it is only meaningful
        # for shared (non private) memory sections.
        if vad.u.VadFlags.PrivateMemory == 1:
            return

        control_area = vad.ControlArea
        if not control_area:
            return

        renderer.format("ControlArea @{0:08x} Segment {1:08x}\n",
                        control_area.dereference().obj_offset, control_area.Segment)

        renderer.format("Dereference list: Flink {0:08x}, Blink {1:08x}\n",
                        control_area.DereferenceList.Flink,
                        control_area.DereferenceList.Blink)

        renderer.format("NumberOfSectionReferences: {0:10} NumberOfPfnReferences:  "
                        "{1:10}\n", control_area.NumberOfSectionReferences,
                        control_area.NumberOfPfnReferences)

        renderer.format("NumberOfMappedViews:       {0:10} NumberOfUserReferences: "
                        "{1:10}\n", control_area.NumberOfMappedViews,
                        control_area.NumberOfUserReferences)

        renderer.format("WaitingForDeletion Event:  {0:08x}\n",
                        control_area.WaitingForDeletion)

        renderer.format("Control Flags: {0}\n", control_area.u.Flags)

        file_object = vad.ControlArea.FilePointer.dereference()
        if file_object and file_object != 0:
            renderer.format("FileObject @{0:08x} FileBuffer @ {1:08x}          , "
                            "Name: {2}\n", file_object.obj_offset,
                            file_object.FileName.Buffer, file_object.FileName)

    def write_vad_ext(self, renderer, vad):
        """Renders a text version of a Long Vad"""
        if vad.obj_type != "_MMVAD_SHORT":
            renderer.format("First prototype PTE: {0:08x} Last contiguous PTE: "
                            "{1:08x}\n", vad.FirstPrototypePte, vad.LastContiguousPte)

            renderer.format("Flags2: {0}\n", vad.u2.VadFlags2)



class VADTree(VADInfo):
    """Walk the VAD tree and display in tree format"""

    __name = "vadtree"

    def render(self, renderer):
        for task in self.filter_processes():
            renderer.section()
            renderer.format(u"Pid: {0:6}\n", task.UniqueProcessId)

            renderer.table_header([("indent", "indent", ""),
                                   ("Start", "Start", "[addrpad]"),
                                   ("-","-", ""),
                                   ("End","End", "[addrpad]")
                                   ], suppress_headers=True)

            levels = {}
            for vad in task.RealVadRoot.traverse():
                level = levels.get(vad.Parent.v(), -1) + 1
                levels[vad.obj_offset] = level
                renderer.table_row(u" " * level, vad.Start, vad.End)

    def render_dot(self, outfd):
        for task in self.filter_processes():
            outfd.write(u"/" + "*" * 72 + "/\n")
            outfd.write(u"/* Pid: {0:6} */\n".format(task.UniqueProcessId))
            outfd.write(u"digraph processtree {\n")
            outfd.write(u"graph [rankdir = \"TB\"];\n")
            for vad in task.RealVadRoot.traverse():
                if vad.Parent and vad.Parent.dereference():
                    outfd.write(u"vad_{0:08x} -> vad_{1:08x}\n".format(
                            vad.Parent.v() or 0, vad.obj_offset))

                outfd.write(
                    u"vad_{0:08x} [label = \"{{ {1}\\n{2:08x} - {3:08x} }}\""
                    "shape = \"record\" color = \"blue\"];\n".format(
                        vad.obj_offset, vad.Tag, vad.Start, vad.End))

            outfd.write(u"}\n")


class VADWalk(VADInfo):
    """Walk the VAD tree"""

    __name = "vadwalk"

    def render(self, renderer):
        for task in self.filter_processes():
            renderer.section()
            renderer.format(u"Pid: {0:6}\n", task.UniqueProcessId)
            renderer.table_header([("Address", "address", "[addrpad]"),
                                   ("Parent", "parent", "[addrpad]"),
                                   ("Left", "left", "[addrpad]"),
                                   ("Right", "right", "[addrpad]"),
                                   ("Start", "start", "[addrpad]"),
                                   ("End", "end", "[addrpad]"),
                                   ("Tag", "tag", "4"),
                                   ])
            for vad in task.RealVadRoot.traverse():
                # Ignore Vads with bad tags (which we explicitly include as None)
                if vad:
                    renderer.table_row(vad.obj_offset,
                                       vad.Parent.obj_offset or 0,
                                       vad.LeftChild.dereference().obj_offset or 0,
                                       vad.RightChild.dereference().obj_offset or 0,
                                       vad.Start,
                                       vad.End,
                                       vad.Tag)

class VADDump(VADInfo):
    """Dumps out the vad sections to a file"""

    __name = "vaddump"

    def __init__(self, dump_dir=None, verbose=False, **kwargs):
        """Dump all the memory reserved for a process in its vad tree.

        Args:
           dump_dir: Directory in which to dump the VAD files
           verbose: Print verbose progress information
        """
        super(VADDump, self).__init__(**kwargs)
        if self.session:
            dump_dir = dump_dir or self.session.dump_dir

        self.dump_dir = dump_dir
        if self.dump_dir is None:
            raise plugin.PluginError("Dump directory not specified.")

        if not os.path.isdir(self.dump_dir):
            debug.error(self.dump_dir + " is not a directory")

        self.verbose = verbose

    def render(self, renderer):
        for task in self.filter_processes():
            renderer.section()
            renderer.format("Pid: {0:6}\n", task.UniqueProcessId)

            # Get the task and all process specific information
            task_space = task.get_process_address_space()

            name = task.ImageFileName
            offset = task_space.vtop(task.obj_offset)
            if offset is None:
                renderer.format("Process does not have a valid address space.\n")
                continue

            for vad in task.RealVadRoot.traverse():
                # Ignore Vads with bad tags
                if vad.obj_type == "_MMVAD":
                    continue

                # Find the start and end range
                start = vad.Start
                end = vad.End

                filename = "{0}.{1:x}.{2:08x}-{3:08x}.dmp".format(
                    name, offset, start, end)

                # Open the file and initialize the data
                path = os.path.join(self.dump_dir, filename)

                with open(path, 'wb') as fd:
                    self.session.report_progress("Dumping %s" % filename)
                    self.CopyToFile(task_space, start, end + 1, fd)

    def CopyToFile(self, addrspace, start, end, outfd):
        """Copy a part of the address space to the output file.

        This utility function allows the writing of sparse files correctly. We
        pass over the address space, automatically skipping regions which are
        not valid. For file systems which support sparse files (e.g. in Linux),
        no additional disk space will be used for unmapped regions.

        If a region has no mapped pages, the resulting file will be of 0 bytes
        long.
        """
        BUFFSIZE = 1024 * 1024

        for offset, length in addrspace.get_address_ranges(start, end):
            outfd.seek(offset - start)
            i = offset

            # Now copy the region in fixed size buffers.
            while i < offset + length:
                to_read = min(BUFFSIZE, length)

                data = addrspace.zread(i, to_read)
                outfd.write(data)

                i += to_read


class VAD(common.WinProcessFilter):
    """Concise dump of the VAD.

    Similar to windbg's !vad.
    """

    __name = "vad"

    PAGE_SIZE = 12

    def render_vadroot(self, renderer, vad_root):
        renderer.table_header([('VAD', 'offset', '[addrpad]'),
                               ('lev', 'depth', '<2'),
                               ('start', 'start_pfn', '[addr]'),
                               ('end', 'end_pfn', '[addr]'),
                               ('com', 'com', '!>4'),
                               ('', 'type', '7'),
                               ('', 'executable', '6'),
                               ('Protect', 'protection', '!20'),
                               ('Filename', 'filename', '')])

        for vad in vad_root.traverse():
            filename = ""
            try:
                file_obj = vad.ControlArea.FilePointer
                if file_obj:
                    filename = file_obj.FileName or "Pagefile-backed section"
            except AttributeError:
                pass

            renderer.table_row(
                vad.obj_offset, vad.obj_context.get('depth', 0),
                vad.Start >> self.PAGE_SIZE,
                vad.End >> self.PAGE_SIZE,
                vad.CommitCharge if vad.CommitCharge < 0x7FFFFFFFFFFFF else -1,
                "Private" if vad.u.VadFlags.PrivateMemory > 0 else "Mapped",
                "Exe" if "EXECUTE" in str(vad.u.VadFlags.ProtectionEnum) else "",
                vad.u.VadFlags.ProtectionEnum,
                filename)

    def render(self, renderer):
        for task in self.filter_processes():
            renderer.section()
            renderer.format("Pid: {0} {1}\n", task.UniqueProcessId,
                            task.ImageFileName)
            self.render_vadroot(renderer, task.RealVadRoot)


class VadScanner(scan.BaseScanner):
    """A scanner over all memory regions of a process."""

    def __init__(self, task=None, process_profile=None):
        """Scan the process address space through the Vads.

        Args:
          task: The _EPROCESS object for this task.

          process_profile: The specialized profile for this process. In practice
            this is always different from task.obj_profile (which belongs to the
            kernel). If not provided we default to the kernel profile.
        """
        self.task = task
        super(VadScanner, self).__init__(
            profile=process_profile or task.obj_profile,
            address_space=task.get_process_address_space())

    def scan(self, offset=0, maxlen=sys.maxint):
        for vad in self.task.RealVadRoot.traverse():
            for match in super(VadScanner, self).scan(
                vad.Start, vad.End - vad.Start + 1):
                yield match
