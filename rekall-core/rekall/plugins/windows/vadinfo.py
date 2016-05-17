# Rekall Memory Forensics
#
# Based on the source code from
# Volatools Basic
# Copyright (C) 2007 Komoku, Inc.
# Copyright 2013 Google Inc. All Rights Reserved.
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

# pylint: disable=protected-access

import re

from rekall import scan
from rekall import utils
from rekall.plugins import core
from rekall.plugins.addrspaces import intel
from rekall.plugins.common import pfn
from rekall.plugins.windows import address_resolver
from rekall.plugins.windows import common
from rekall.plugins.windows import pagefile


class VADInfo(common.WinProcessFilter):
    """Dump the VAD info"""

    __name = "vadinfo"

    def render(self, renderer):
        for task in self.filter_processes():
            renderer.section()
            renderer.format("Pid: {0:6}\n", task.UniqueProcessId)

            count = 0
            for count, vad in enumerate(task.RealVadRoot.traverse()):
                try:
                    self.write_vad_short(renderer, vad)
                except AttributeError:
                    pass

                try:
                    self.write_vad_control(renderer, vad)
                except AttributeError:
                    pass

                try:
                    self.write_vad_ext(renderer, vad)
                except AttributeError:
                    pass

                renderer.format("\n")

            self.session.report_progress("Pid %s: %s Vads" % (
                task.UniqueProcessId, count))

    def write_vad_short(self, renderer, vad):
        """Renders a text version of a Short Vad"""
        renderer.table_header([("VAD node @", "offset", ""),
                               ("address", "address", "[addrpad]"),
                               ("Start", "Start", "5"),
                               ("startaddr", "startaddr", "[addrpad]"),
                               ("End", "End", "3"),
                               ("endaddr", "endaddr", "[addrpad]"),
                               ("Tag", "Tag", "3"),
                               ("tagval", "tagval", ""),
                              ], suppress_headers=True)
        renderer.table_row("VAD node @",
                           vad.obj_offset,
                           "Start",
                           vad.Start,
                           "End",
                           vad.End,
                           "Tag",
                           vad.Tag)

        renderer.format("Flags: {0}\n", vad.u.VadFlags)

        # although the numeric value of Protection is printed above with
        # VadFlags, let's show the user a human-readable translation of the
        # protection
        renderer.format("Protection: {0}\n", vad.u.VadFlags.ProtectionEnum)

        # translate the vad type if its available (> XP)
        if vad.u.VadFlags.m("VadType"):
            renderer.format("Vad Type: {0}\n", vad.u.VadFlags.VadTypeEnum)

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
                        control_area.dereference().obj_offset,
                        control_area.Segment)

        renderer.format("Dereference list: Flink {0:08x}, Blink {1:08x}\n",
                        control_area.DereferenceList.Flink,
                        control_area.DereferenceList.Blink)

        renderer.format(
            "NumberOfSectionReferences: {0:10} NumberOfPfnReferences:  "
            "{1:10}\n", control_area.NumberOfSectionReferences,
            control_area.NumberOfPfnReferences)

        renderer.format(
            "NumberOfMappedViews:       {0:10} NumberOfUserReferences: "
            "{1:10}\n", control_area.NumberOfMappedViews,
            control_area.NumberOfUserReferences)

        renderer.format(
            "WaitingForDeletion Event:  {0:08x}\n",
            control_area.WaitingForDeletion)

        renderer.format(
            "Control Flags: {0}\n", control_area.u.Flags)

        file_object = control_area.FilePointer
        if file_object and file_object != 0:
            renderer.format(
                "FileObject @{0:08x} FileBuffer @ {1:08x}          , "
                "Name: {2}\n", file_object.obj_offset,
                file_object.FileName.Buffer, file_object.FileName)

    def write_vad_ext(self, renderer, vad):
        """Renders a text version of a Long Vad"""
        if vad.obj_type != "_MMVAD_SHORT":
            renderer.format(
                "First prototype PTE: {0:08x} Last contiguous PTE: "
                "{1:08x}\n", vad.FirstPrototypePte[0],
                vad.LastContiguousPte)

            renderer.format("Flags2: {0}\n", vad.u2.VadFlags2)



class VADTree(VADInfo):
    """Walk the VAD tree and display in tree format"""

    __name = "vadtree"

    def render(self, renderer):
        for task in self.filter_processes():
            renderer.section()
            renderer.format(u"Pid: {0:6}\n", task.UniqueProcessId)

            renderer.table_header([
                dict(name="", type="TreeNode", width=1),
                ("Start", "start", "[addrpad]"),
                ("-", "-", ""),
                ("End", "End", "[addrpad]")
                ], suppress_headers=True)

            for vad in task.RealVadRoot.traverse():
                level = vad.obj_context.get('depth', 0)
                renderer.table_row("", vad.Start, "->", vad.End, depth=level)


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
                # Ignore Vads with bad tags (which we explicitly include as
                # None)
                if vad:
                    renderer.table_row(
                        vad.obj_offset,
                        vad.obj_parent.obj_offset,
                        vad.LeftChild.v(),
                        vad.RightChild.v(),
                        vad.Start,
                        vad.End,
                        vad.Tag)

class VAD(common.WinProcessFilter):
    """Concise dump of the VAD.

    Similar to windbg's !vad.
    """

    __name = "vad"

    @classmethod
    def args(cls, parser):
        super(VAD, cls).args(parser)
        parser.add_argument(
            "--regex", default=None,
            help="A regular expression to filter VAD filenames.")

        parser.add_argument(
            "--offset", default=None, type="IntParser",
            help="Only print the vad corresponding to this offset.")

    def __init__(self, *args, **kwargs):
        self.regex = kwargs.pop("regex", None)
        self.offset = kwargs.pop("offset", None)
        self._cache = {}

        # Pass positional args to the WinProcessFilter constructor.
        super(VAD, self).__init__(*args, **kwargs)

    def find_file(self, addr):
        """Finds the file mapped at this address."""
        for task in self.filter_processes():
            yield self.find_file_in_task(addr, task)

    def find_file_in_task(self, addr, task):
        resolver = self.GetVadsForProcess(task)
        if resolver:
            start, end, data = resolver.get_containing_range(addr)
            return data

    def _make_cache(self, task):
        result = utils.RangedCollection()
        self.session.report_progress(
            " Enumerating VADs in %s (%s)", task.name, task.pid)

        for vad in task.RealVadRoot.traverse():
            result.insert(vad.Start, vad.End, (self._get_filename(vad), vad))

        return result

    def GetVadsForProcess(self, task):
        try:
            resolver = self._cache[task]
        except KeyError:
            # Break the recursion by placing a None for the resolver. The
            # self._make_cache() call will run the vad plugin which might
            # resolve a VAD PTE, calling this code. This means that we can only
            # use non-VAD PTEs to read the VAD itself.
            self._cache[task] = None
            resolver = self._cache[task] = self._make_cache(task)

        return resolver

    def _get_filename(self, vad):
        filename = ""
        try:
            file_obj = vad.ControlArea.FilePointer
            if file_obj:
                filename = file_obj.FileName or "Pagefile-backed section"
        except AttributeError:
            pass

        return unicode(filename)

    def render_vadroot(self, renderer, vad_root, task):
        renderer.table_header([('VAD', 'offset', '[addrpad]'),
                               ('lev', 'level', '>3'),
                               ('Start Addr', 'start_pfn', '[addrpad]'),
                               ('End Addr', 'end_pfn', '[addrpad]'),
                               dict(name='com', width=6, align="r"),
                               ('', 'type', '7'),
                               ('', 'executable', '6'),
                               ('Protect', 'protection', '!20'),
                               ('Filename', 'filename', '')])

        task_as = task.get_process_address_space()

        result = []
        for vad in vad_root.traverse():
            # Apply filters if needed.
            if self.regex and not re.search(
                    self.regex, self._get_filename(vad)):
                continue

            if (self.offset is not None and
                    not vad.Start <= self.offset <= vad.End):
                continue

            exe = ""
            if "EXECUTE" in str(vad.u.VadFlags.ProtectionEnum):
                exe = "Exe"

            result.append((
                vad, vad.obj_context.get('depth', 0),

                # The vad region itself exists in the process address space.
                self.profile.Pointer(value=vad.Start, vm=task_as),
                self.profile.Pointer(value=vad.End, vm=task_as),
                vad.CommitCharge if vad.CommitCharge < 0x7fffffff else -1,
                "Private" if vad.u.VadFlags.PrivateMemory > 0 else "Mapped",
                exe,
                vad.u.VadFlags.ProtectionEnum,
                self._get_filename(vad)))

        # Sort by start range.
        result.sort(key=lambda x: x[2].v())
        for row in result:
            renderer.table_row(*row)

    def render(self, renderer):
        for task in self.filter_processes():
            renderer.section()
            renderer.format("Pid: {0} {1}\n", task.UniqueProcessId,
                            task.ImageFileName)
            renderer.RenderProgress("Pid: %s" % task.UniqueProcessId)
            self.render_vadroot(renderer, task.RealVadRoot, task)


class VADMap(pfn.VADMapMixin, common.WinProcessFilter):
    """Inspect each page in the VAD and report its status.

    This allows us to see the address translation status of each page in the
    VAD.
    """

    def _CreateMetadata(self, collection):
        metadata = {}
        for descriptor_cls, _, _ in collection.descriptors:
            # Any of the following kinds of PTE are considered prototype.
            if descriptor_cls in (pagefile.WindowsProtoTypePTEDescriptor,
                                  pagefile.VadPteDescriptor):
                metadata["ProtoType"] = True
                break

        for descriptor_cls, args, kwargs in reversed(collection.descriptors):
            if issubclass(descriptor_cls,
                          pagefile.WindowsSubsectionPTEDescriptor):
                metadata.update(descriptor_cls(
                    session=self.session, *args, **kwargs).metadata())

                return metadata

            elif issubclass(descriptor_cls, pagefile.WindowsPTEDescriptor):
                type = kwargs.get("pte_type")
                if type == "Proto":
                    metadata["ProtoType"] = True

                pte_value = kwargs.get("pte_value")
                if pte_value & 1:
                    metadata["type"] = "Valid"
                else:
                    metadata["type"] = "Transition"

                return metadata

            elif issubclass(descriptor_cls, pagefile.WindowsPagefileDescriptor):
                metadata["number"] = kwargs.get("pagefile_number", 0)
                metadata["offset"] = kwargs.get("address", 0)
                metadata["type"] = "Pagefile"

                return metadata

            elif issubclass(descriptor_cls, pagefile.DemandZeroDescriptor):
                metadata["type"] = "Demand Zero"
                return metadata

            elif issubclass(descriptor_cls, intel.PhysicalAddressDescriptor):
                metadata["offset"] = kwargs["address"]
                metadata.setdefault("type", "Valid")

            elif issubclass(descriptor_cls, intel.InvalidAddress):
                metadata["type"] = "Invalid"

        return metadata

    def _GenerateVADRuns(self, vad):
        address_space = self.session.GetParameter("default_address_space")

        offset = vad.Start
        end = min(vad.End, self.plugin_args.end)

        while offset < end:
            if self.plugin_args.start <= offset <= self.plugin_args.end:
                yield offset, self._CreateMetadata(
                    address_space.describe_vtop(offset))

                self.session.report_progress("Inspecting 0x%08X", offset)

            offset += 0x1000

    def GeneratePageMetatadata(self, task):
        for module in self.session.address_resolver.modules():
            if isinstance(module, address_resolver.VadModule):
                # Skip guard regions for Wow64.
                if module.vad.CommitCharge >= 0x7fffffff:
                    continue

                for vaddr, metadata in self._GenerateVADRuns(module.vad):
                    yield vaddr, metadata


class VADDump(core.DirectoryDumperMixin, VAD):
    """Dumps out the vad sections to a file"""

    __name = "vaddump"

    @classmethod
    def args(cls, parser):
        super(VADDump, cls).args(parser)
        parser.add_argument("--max_size", type="IntParser",
                            default=100*1024*1024,
                            help="Maximum file size to dump.")

    def __init__(self, *args, **kwargs):
        self.max_size = kwargs.pop("max_size", 100*1024*1024)
        super(VADDump, self).__init__(*args, **kwargs)

    def render(self, renderer):
        for task in self.filter_processes():
            renderer.section("{0:6} ({1:2})".format(
                task.name, task.UniqueProcessId))

            renderer.table_header([
                ("Start", "start", "[addrpad]"),
                ("End", "end", "[addrpad]"),
                ("Length", "length", "[addr]"),
                ("Filename", "filename", "60s"),
                ("Comment", "comment", "")])

            # Get the task and all process specific information
            task_space = task.get_process_address_space()

            name = task.ImageFileName
            offset = task_space.vtop(task.obj_offset)
            if offset is None:
                renderer.format(
                    "Process does not have a valid address space.\n")
                continue

            with self.session.plugins.cc() as cc:
                cc.SwitchProcessContext(task)

                for vad in task.RealVadRoot.traverse():
                    # Find the start and end range
                    start = vad.Start
                    end = vad.End

                    filename = "{0}.{1:x}.{2:08x}-{3:08x}.dmp".format(
                        name, offset, start, end)

                    with renderer.open(directory=self.dump_dir,
                                       filename=filename,
                                       mode='wb') as fd:

                        if end - start > self.max_size:
                            renderer.table_row(start, end, end-start,
                                               "Skipped - Region too large")
                            continue

                        self.session.report_progress("Dumping %s" % filename)

                        self.CopyToFile(task_space, start, end + 1, fd)
                        renderer.table_row(
                            start, end, end-start, filename,
                            self._get_filename(vad))


class VadScanner(scan.BaseScanner):
    """A scanner over all memory regions of a process."""

    def __init__(self, task=None, process_profile=None, **kwargs):
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
            address_space=task.get_process_address_space(),
            **kwargs)

    def scan(self, offset=0, maxlen=None):
        maxlen = maxlen or self.profile.get_constant("MaxPointer")

        for vad in self.task.RealVadRoot.traverse():
            # Only scan the VAD region.
            for match in super(VadScanner, self).scan(vad.Start, vad.Length):
                yield match
