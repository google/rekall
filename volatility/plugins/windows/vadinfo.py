# Volatility
#
# Based on the source code from
# Volatools Basic
# Copyright (C) 2007 Komoku, Inc.
#
# Authors:
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
            for count, vad in enumerate(task.VadRoot.traverse()):
                vad = vad.dereference()
                if vad and vad != 0:
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

    def write_vad_control(self, outfd, vad):
        """Renders a text version of a (non-short) Vad's control information"""
        # even if the ControlArea is not NULL, it is only meaningful
        # for shared (non private) memory sections.
        if vad.u.VadFlags.PrivateMemory == 1:
            return

        control_area = vad.ControlArea
        if not control_area:
            return

        outfd.write("ControlArea @{0:08x} Segment {1:08x}\n".format(
                control_area.dereference().obj_offset, control_area.Segment))

        outfd.write("Dereference list: Flink {0:08x}, Blink {1:08x}\n".format(
                control_area.DereferenceList.Flink,
                control_area.DereferenceList.Blink))

        outfd.write("NumberOfSectionReferences: {0:10} NumberOfPfnReferences:  "
                    "{1:10}\n".format(
                control_area.NumberOfSectionReferences,
                control_area.NumberOfPfnReferences))

        outfd.write("NumberOfMappedViews:       {0:10} NumberOfUserReferences: "
                    "{1:10}\n".format(
                control_area.NumberOfMappedViews,
                control_area.NumberOfUserReferences))

        outfd.write("WaitingForDeletion Event:  {0:08x}\n".format(
                control_area.WaitingForDeletion))

        outfd.write("Control Flags: {0}\n".format(str(control_area.u.Flags)))

        file_object = vad.ControlArea.FilePointer.dereference()
        if file_object and file_object != 0:
            outfd.write("FileObject @{0:08x} FileBuffer @ {1:08x}          , "
                        "Name: {2}\n".format(
                    file_object.obj_offset, file_object.FileName.Buffer,
                    file_object.FileName))

    def write_vad_ext(self, outfd, vad):
        """Renders a text version of a Long Vad"""
        if vad.obj_type != "_MMVAD_SHORT":
            outfd.write("First prototype PTE: {0:08x} Last contiguous PTE: "
                        "{1:08x}\n".format(
                    vad.FirstPrototypePte, vad.LastContiguousPte))

            outfd.write("Flags2: {0}\n".format(str(vad.u2.VadFlags2)))



class VADTree(VADInfo):
    """Walk the VAD tree and display in tree format"""

    __name = "vadtree"

    def render(self, renderer):
        for task in self.filter_processes():
            renderer.write(u"*" * 72 + "\n")
            renderer.write(u"Pid: {0:6}\n".format(task.UniqueProcessId))

            renderer.table_header([("indent", "indent", ""),
                                   ("Start", "Start", "[addrpad]"),
                                   ("-","-", ""),
                                   ("End","End", "[addrpad]")
                                   ], suppress_headers=True)

            levels = {}
            for vad in task.VadRoot.traverse():
                vad = vad.dereference()
                if vad:
                    level = levels.get(vad.Parent.v(), -1) + 1
                    levels[vad.obj_offset] = level
                    renderer.table_row(u" " * level, vad.Start, vad.End)

    def render_dot(self, outfd):
        for task in self.filter_processes():
            outfd.write(u"/" + "*" * 72 + "/\n")
            outfd.write(u"/* Pid: {0:6} */\n".format(task.UniqueProcessId))
            outfd.write(u"digraph processtree {\n")
            outfd.write(u"graph [rankdir = \"TB\"];\n")
            for vad in task.VadRoot.traverse():
                vad = vad.dereference()
                if vad:
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

    def render(self, outfd):
        for task in self.filter_processes():
            outfd.write(u"*" * 72 + "\n")
            outfd.write(u"Pid: {0:6}\n".format(task.UniqueProcessId))
            outfd.write(u"{0:16s} {1:16s} {2:16s} {3:16s} {4:16s} {5:16s} {6:4}\n".format(
                    "Address", "Parent", "Left", "Right", "Start", "End", "Tag"))
            for vad in task.VadRoot.traverse():
                # Ignore Vads with bad tags (which we explicitly include as None)
                vad = vad.dereference()
                if vad:
                    outfd.write(u"{0:016x} {1:016x} {2:016x} {3:016x} {4:016x} {5:016x} {6:4}\n".format(
                        vad.obj_offset,
                        vad.Parent.v() or 0,
                        vad.LeftChild.dereference().obj_offset or 0,
                        vad.RightChild.dereference().obj_offset or 0,
                        vad.Start, vad.End, vad.Tag))

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

    def render(self, outfd):
        for task in self.filter_processes():
            outfd.write("Pid: {0:6}\n".format(task.UniqueProcessId))
            # Get the task and all process specific information
            task_space = task.get_process_address_space()
            name = task.ImageFileName
            offset = task_space.vtop(task.obj_offset)
            if offset is None:
                outfd.write("Process does not have a valid address space.\n")
                continue

            outfd.write("*" * 72 + "\n")
            for vad in task.VadRoot.traverse():
                vad = vad.dereference()
                if not vad: continue

                # Ignore Vads with bad tags
                if vad.obj_type == "_MMVAD":
                    continue

                # Find the start and end range
                start = vad.Start
                end = vad.End

                # Open the file and initialize the data
                path = os.path.join(
                    self.dump_dir, "{0}.{1:x}.{2:08x}-{3:08x}.dmp".format(
                        name, offset, start, end))

                with open(path, 'wb') as f:
                    # Copy the memory from the process's address space into the
                    # file. This will null pad any missing pages.
                    range_data = task_space.zread(start, end - start + 1)

                    if self.verbose:
                        outfd.write("Writing VAD for %s\n" % path)

                    f.write(range_data)

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
            vad = vad.dereference()
            if not vad: continue

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
                vad.u.VadFlags.CommitCharge,
                "Private" if vad.u.VadFlags.PrivateMemory else "Mapped",
                "Exe" if "EXECUTE" in str(vad.u.VadFlags.ProtectionEnum) else "",
                vad.u.VadFlags.ProtectionEnum,
                filename)

    def render(self, renderer):
        for task in self.filter_processes():
            renderer.section()
            renderer.format("Pid: {0} {1}\n", task.UniqueProcessId,
                            task.ImageFileName)
            self.render_vadroot(renderer, task.VadRoot)


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

    def scan(self, offset=0, maxlen=None):
        for vad in self.task.VadRoot.traverse():
            for match in super(VadScanner, self).scan(
                vad.Start, vad.End - vad.Start):
                yield match
