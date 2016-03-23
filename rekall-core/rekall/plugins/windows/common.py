# Rekall Memory Forensics
#
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Authors:
# Michael Cohen <scudette@users.sourceforge.net>
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

""" This plugin contains CORE classes used by lots of other plugins """

# pylint: disable=protected-access

import re

from rekall import addrspace
from rekall import scan
from rekall import obj
from rekall import kb
from rekall import plugin
from rekall import utils

from rekall.plugins import core

# Windows kernel pdb filenames.
KERNEL_NAMES = set(
    ["ntkrnlmp.pdb", "ntkrnlpa.pdb", "ntoskrnl.pdb",
     "ntkrpamp.pdb"])


# We require both a physical AS set and a valid profile for
# AbstractWindowsCommandPlugins.

class AbstractWindowsCommandPlugin(plugin.PhysicalASMixin,
                                   plugin.ProfileCommand):
    """A base class for all windows based plugins.

    Windows based plugins require at a minimum a working profile, and a valid
    physical address space.
    """

    __abstract = True

    @classmethod
    def is_active(cls, session):
        """We are only active if the profile is windows."""
        return (super(AbstractWindowsCommandPlugin, cls).is_active(session) and
                session.profile.metadata("os") == 'windows')


class AbstractWindowsParameterHook(kb.ParameterHook):

    @classmethod
    def is_active(cls, session):
        """We are only active if the profile is windows."""
        return (super(AbstractWindowsParameterHook, cls).is_active(session) and
                session.profile.metadata("os") == 'windows')


class WinDTBScanner(scan.BaseScanner):
    def __init__(self, process_name=None, **kwargs):
        super(WinDTBScanner, self).__init__(**kwargs)
        needle_process_name = process_name or "Idle"
        needle = needle_process_name + "\x00" * (15 - len(needle_process_name))
        self.image_name_offset = self.profile.get_obj_offset(
            "_EPROCESS", "ImageFileName")
        self.checks = [["StringCheck", {"needle": needle}]]

    def scan(self, offset=0, maxlen=None):
        for offset in super(WinDTBScanner, self).scan(offset, maxlen):
            self.eprocess = self.profile.Object(
                "_EPROCESS", offset=offset - self.image_name_offset,
                vm=self.session.physical_address_space)
            self.session.logging.debug("Found _EPROCESS @ 0x%X (DTB: 0x%X)",
                                       self.eprocess.obj_offset,
                                       self.eprocess.Pcb.DirectoryTableBase.v())

            yield self.eprocess


class WinFindDTB(AbstractWindowsCommandPlugin, core.FindDTB):
    """A plugin to search for the Directory Table Base for windows systems.

    There are a number of ways to find the DTB:

    - Scanner method: Scans the image for a known kernel process, and read the
      DTB from its Process Environment Block (PEB).

    - Get the DTB from the KPCR structure.

    - Note that the kernel is mapped into every process's address space (with
      the exception of session space which might be different) so using any
      process's DTB from the same session will work to read kernel data
      structures. If this plugin fails, try psscan to find potential DTBs.
    """

    __name = "find_dtb"

    @classmethod
    def args(cls, parser):
        """Declare the command line args we need."""
        super(WinFindDTB, cls).args(parser)
        parser.add_argument("--process_name",
                            help="The name of the process to search for.")

    def __init__(self, process_name="Idle", **kwargs):
        super(WinFindDTB, self).__init__(**kwargs)
        self.process_name = process_name
        self.eprocess_index = self.session.LoadProfile("nt/eprocess_index")

    def scan_for_process(self):
        """Scan the image for the idle process."""
        for process in WinDTBScanner(
                session=self.session, process_name=self.process_name,
                profile=self.profile,
                address_space=self.physical_address_space).scan():
            yield process

    def address_space_hits(self):
        """Finds DTBs and yields virtual address spaces that expose kernel.

        Yields:
          BaseAddressSpace-derived instances, validated using the VerifyHit()
          method.
        """
        for dtb, eprocess in self.dtb_eprocess_hits():
            address_space = self.VerifyHit(dtb)
            if address_space is not None and self.TestEProcess(
                    address_space, eprocess):
                yield address_space

    def dtb_eprocess_hits(self):
        for eprocess in self.scan_for_process():
            result = eprocess.Pcb.DirectoryTableBase.v()
            if result:
                yield result, eprocess

    def TestEProcess(self, address_space, eprocess):
        # Reflect through the address space at ourselves. Note that the Idle
        # process is not usually in the PsActiveProcessHead list, so we use
        # the ThreadListHead instead.
        list_head = eprocess.ThreadListHead.Flink

        if list_head == 0:
            self.session.logging.debug("_EPROCESS.ThreadListHead not valid.")
            return

        me = list_head.dereference(vm=address_space).Blink.Flink
        if me.v() != list_head.v():
            self.session.logging.debug(
                "_EPROCESS.ThreadListHead does not reflect.")
            return

        # We passed the tests.X
        return True

    def VerifyHit(self, dtb):
        """Check the eprocess for sanity."""
        # In windows the DTB must be page aligned, except for PAE images where
        # its aligned to a 0x20 size.
        if not self.profile.metadata("pae") and dtb & 0xFFF != 0:
            return

        if self.profile.metadata("pae") and dtb & 0xF != 0:
            return

        # Select simple address space implementations as test address spaces.
        address_space = super(WinFindDTB, self).GetAddressSpaceImplementation()(
            session=self.session, dtb=dtb,
            base=self.session.physical_address_space)

        # Check that the _KUSER_SHARED_DATA makes sense. This structure is
        # always at a known offset since it must be shared with user space apps.
        kuser_shared = self.eprocess_index._KUSER_SHARED_DATA(
            offset=self.profile.get_constant("KI_USER_SHARED_DATA"),
            vm=address_space)

        # Must be a valid version of windows.
        if (address_space.vtop(kuser_shared.obj_offset) and
                (kuser_shared.NtMajorVersion not in [5, 6, 10] or
                 kuser_shared.NtMinorVersion not in [0, 1, 2, 3])):
            return

        self.session.SetCache("dtb", dtb)

        return self.CreateAS(dtb)

    def GetAddressSpaceImplementation(self):
        """Returns the correct address space class for this profile."""
        # The virtual address space implementation is chosen by the profile.
        architecture = self.profile.metadata("arch")
        performance = self.session.GetParameter("performance")
        if architecture == "AMD64":
            # If the user prefers performance we will use the simplest Address
            # Space Implementation.
            if performance == "fast":
                impl = "AMD64PagedMemory"
            else:
                impl = "WindowsAMD64PagedMemory"

        # PAE profiles go with the pae address space.
        elif architecture == "I386" and self.profile.metadata("pae"):
            if performance == "fast":
                impl = "IA32PagedMemoryPae"
            else:
                impl = "WindowsIA32PagedMemoryPae"

        else:
            return super(WinFindDTB, self).GetAddressSpaceImplementation()

        as_class = addrspace.BaseAddressSpace.classes[impl]
        return as_class

    def render(self, renderer):
        renderer.table_header(
            [("_EPROCESS (P)", "physical_eprocess", "[addrpad]"),
             ("DTB", "dtv", "[addrpad]"),
             ("Valid", "valid", "10")])

        for dtb, eprocess in self.dtb_eprocess_hits():
            renderer.table_row(
                eprocess.obj_offset, dtb,
                self.VerifyHit(dtb) is not None)


## The following are checks for pool scanners.

class PoolTagCheck(scan.StringCheck):
    """This scanner checks for the occurrence of a pool tag.

    It is basically a StringCheck but it offsets the check with a constant.
    """
    def __init__(self, tag=None, **kwargs):
        super(PoolTagCheck, self).__init__(needle=tag, **kwargs)

        # The offset from the start of _POOL_HEADER to the tag. (Note we use the
        # kernel profile for pool definitions.).
        self.tag_offset = self.session.profile.get_obj_offset(
            "_POOL_HEADER", "PoolTag")

    def skip(self, buffer_as, offset):
        return super(PoolTagCheck, self).skip(
            buffer_as, offset + self.tag_offset)

    def check(self, buffer_as, offset):
        return super(PoolTagCheck, self).check(
            buffer_as, offset + self.tag_offset)


class MultiPoolTagCheck(scan.MultiStringFinderCheck):
    """This scanner checks for the occurrence of a pool tag.

    It is basically a StringCheck but it offsets the check with a constant.
    """
    def __init__(self, tags=None, **kwargs):
        super(MultiPoolTagCheck, self).__init__(needles=tags, **kwargs)

        # The offset from the start of _POOL_HEADER to the tag.
        self.tag_offset = self.profile.get_obj_offset(
            "_POOL_HEADER", "PoolTag")

    def skip(self, buffer_as, offset):
        return super(MultiPoolTagCheck, self).skip(
            buffer_as, offset + self.tag_offset)

    def check(self, buffer_as, offset):
        return super(MultiPoolTagCheck, self).check(
            buffer_as, offset + self.tag_offset)


class CheckPoolSize(scan.ScannerCheck):
    """ Check pool block size """
    def __init__(self, condition=None, min_size=None, **kwargs):
        super(CheckPoolSize, self).__init__(**kwargs)
        self.condition = condition
        if min_size:
            self.condition = lambda x: x >= min_size

        self.pool_align = self.session.profile.constants['PoolAlignment']
        if self.condition is None:
            raise RuntimeError("No pool size provided")

    def check(self, buffer_as, offset):
        pool_hdr = self.session.profile._POOL_HEADER(
            vm=buffer_as, offset=offset)

        block_size = pool_hdr.BlockSize.v()
        return self.condition(block_size * self.pool_align)


class CheckPoolType(scan.ScannerCheck):
    """ Check the pool type """
    def __init__(self, paged=False, non_paged=False, free=False, **kwargs):
        super(CheckPoolType, self).__init__(**kwargs)
        self.non_paged = non_paged
        self.paged = paged
        self.free = free

    def check(self, buffer_as, offset):
        pool_hdr = self.session.profile._POOL_HEADER(
            vm=buffer_as, offset=offset)

        return ((self.non_paged and pool_hdr.NonPagedPool) or
                (self.free and pool_hdr.FreePool) or
                (self.paged and pool_hdr.PagedPool))


class CheckPoolIndex(scan.ScannerCheck):
    """ Checks the pool index """
    def __init__(self, value=0, **kwargs):
        super(CheckPoolIndex, self).__init__(**kwargs)
        self.value = value

    def check(self, buffer_as, offset):
        pool_hdr = self.session.profile._POOL_HEADER(
            vm=buffer_as, offset=offset)

        return pool_hdr.PoolIndex == self.value


class PoolScanner(scan.BaseScanner):
    """A scanner for pool allocations."""

    def scan(self, offset=0, maxlen=None):
        """Yields instances of _POOL_HEADER which potentially match."""

        maxlen = maxlen or self.session.profile.get_constant("MaxPointer")
        for hit in super(PoolScanner, self).scan(offset=offset, maxlen=maxlen):
            yield self.session.profile._POOL_HEADER(
                vm=self.address_space, offset=hit)


class PoolScannerPlugin(plugin.KernelASMixin, AbstractWindowsCommandPlugin):
    """A base class for all pool scanner plugins."""
    __abstract = True

    @classmethod
    def args(cls, parser):
        super(PoolScannerPlugin, cls).args(parser)
        parser.add_argument(
            "--scan_in_kernel", default=False, type="Boolean",
            help="Scan in the kernel address space")

    def __init__(self, address_space=None, scan_in_kernel=False, **kwargs):
        """Scan the address space for pool allocations.

        Args:
          address_space: If provided we scan this address space, else we use the
          physical_address_space.

          scan_in_kernel: Scan in the kernel address space.
        """
        super(PoolScannerPlugin, self).__init__(**kwargs)
        scan_in_kernel = scan_in_kernel or self.session.scan_in_kernel
        if scan_in_kernel:
            self.address_space = address_space or self.kernel_address_space
        else:
            self.address_space = address_space or self.physical_address_space


class KDBGHook(AbstractWindowsParameterHook):
    """A Hook to calculate the KDBG when needed."""

    name = "kdbg"

    def calculate(self):
        # Try to just get the KDBG address using the profile.
        kdbg = self.session.profile.get_constant_object(
            "KdDebuggerDataBlock", "_KDDEBUGGER_DATA64",
            vm=self.session.kernel_address_space)

        # Verify it.
        if kdbg.Header.OwnerTag == "KDBG":
            return kdbg

        # Cant find it from the profile, look for it the old way.
        self.session.logging.info(
            "KDBG not provided - Rekall will try to "
            "automatically scan for it now using plugin.kdbgscan.")

        for kdbg in self.session.plugins.kdbgscan(
                session=self.session).hits():
            # Just return the first one
            self.session.logging.info(
                "Found a KDBG hit %r. Hope it works. If not try setting it "
                "manually.", kdbg)

            return kdbg


class PsActiveProcessHeadHook(AbstractWindowsParameterHook):
    """The PsActiveProcessHead is actually found in the profile symbols."""

    name = "PsActiveProcessHead"

    def calculate(self):
        return self.session.profile.get_constant_object(
            "PsActiveProcessHead",
            target="_LIST_ENTRY",
            vm=self.session.kernel_address_space)


class PsLoadedModuleList(AbstractWindowsParameterHook):
    """The PsLoadedModuleList is actually found in the profile symbols."""

    name = "PsLoadedModuleList"

    def calculate(self):
        return self.session.profile.get_constant_object(
            "PsLoadedModuleList",
            target="_LIST_ENTRY",
            vm=self.session.kernel_address_space)


class WindowsCommandPlugin(plugin.KernelASMixin, AbstractWindowsCommandPlugin):
    """A windows plugin which requires the kernel address space."""
    __abstract = True


class WinProcessFilter(WindowsCommandPlugin):
    """A class for filtering processes."""

    __abstract = True

    @classmethod
    def args(cls, parser):
        """Declare the command line args we need."""
        super(WinProcessFilter, cls).args(parser)

        parser.add_argument("--eprocess",
                            type="ArrayIntParser",
                            help="Kernel addresses of eprocess structs.")

        parser.add_argument("--phys_eprocess",
                            type="ArrayIntParser",
                            help="Physical addresses of eprocess structs.")

        parser.add_argument("--pid",
                            type="ArrayIntParser",
                            help="One or more pids of processes to select.")

        parser.add_argument("--proc_regex", default=None, type="RegEx",
                            help="A regex to select a process by name.")

        parser.add_argument(
            "--method", choices=cls.METHODS, type="ChoiceArray",
            default=cls.METHODS,
            help="Method to list processes.")

    def __init__(self, pid=None, eprocess=None, phys_eprocess=None,
                 proc_regex=None, method=None, **kwargs):
        """Filters processes by parameters.

        Args:
           physical_eprocess: One or more EPROCESS structs or offsets defined in
              the physical AS.

           pid: A single pid.

           proc_regex: A regular expression for filtering process name (using
             _EPROCESS.ImageFileName).

           method: Methods to use for process listing.
        """
        super(WinProcessFilter, self).__init__(**kwargs)
        self.methods = method or self.METHODS

        if isinstance(phys_eprocess, (int, long)):
            phys_eprocess = [phys_eprocess]
        elif phys_eprocess is None:
            phys_eprocess = []

        if isinstance(eprocess, (int, long)):
            eprocess = [eprocess]
        elif isinstance(eprocess, obj.Struct):
            eprocess = [eprocess.obj_offset]
        elif eprocess is None:
            eprocess = []

        # Convert the physical eprocess offsets to virtual addresses.
        for phys_offset in phys_eprocess:
            virtual_offset = self.virtual_process_from_physical_offset(
                phys_offset)
            if virtual_offset:
                eprocess.append(virtual_offset)

        self.eprocess = eprocess

        pids = []
        if isinstance(pid, list):
            pids.extend(pid)

        elif isinstance(pid, (int, long)):
            pids.append(pid)

        self.pids = pids

        self.proc_regex_text = proc_regex
        if isinstance(proc_regex, basestring):
            proc_regex = re.compile(proc_regex, re.I)

        self.proc_regex = proc_regex

        # Sometimes its important to know if any filtering is specified at all.
        self.filtering_requested = bool(self.pids or self.proc_regex or
                                        self.eprocess)

    def filter_processes(self):
        """Filters eprocess list using phys_eprocess and pids lists."""
        # If eprocess are given specifically only use those.
        if self.eprocess:
            for task in self.list_from_eprocess():
                yield task

        else:
            for proc in self.list_eprocess():
                if not self.filtering_requested:
                    yield proc

                else:
                    if int(proc.pid) in self.pids:
                        yield proc

                    elif self.proc_regex and self.proc_regex.match(
                            utils.SmartUnicode(proc.name)):
                        yield proc

    def virtual_process_from_physical_offset(self, physical_offset):
        """Tries to return an eprocess in virtual space from a physical offset.

        We do this by reflecting off the list elements.

        Args:
           physical_offset: The physcial offset of the process.

        Returns:
           an _EPROCESS object or a NoneObject on failure.
        """
        physical_eprocess = self.profile._EPROCESS(
            offset=int(physical_offset),
            vm=self.physical_address_space)

        return physical_eprocess.ThreadListHead.reflect(
            vm=self.kernel_address_space).dereference_as(
                "_EPROCESS", "ThreadListHead")

    def list_from_eprocess(self):
        for eprocess_offset in self.eprocess:
            eprocess = self.profile._EPROCESS(
                offset=eprocess_offset, vm=self.kernel_address_space)

            yield eprocess

    def list_eprocess(self):
        """List processes using chosen methods."""
        # We actually keep the results from each method around in case we need
        # to find out later which process was revealed by which method.
        seen = set()
        for proc in self.list_from_eprocess():
            seen.add(proc.obj_offset)

        for method in self.METHODS:
            if method in self.methods:
                for proc in self.session.GetParameter("pslist_%s" % method):
                    seen.add(proc)

        # Sort by pid so that the output ordering remains stable.
        result = []
        for x in seen:
            result.append(self.profile._EPROCESS(
                x, vm=self.session.kernel_address_space))

        return sorted(result, key=lambda x: x.pid)

    # Maintain the order of methods.
    METHODS = [
        "PsActiveProcessHead",
        "CSRSS",
        "PspCidTable",
        "Sessions",
        "Handles",
        ]


class PsListPsActiveProcessHeadHook(AbstractWindowsParameterHook):
    name = "pslist_PsActiveProcessHead"

    def calculate(self):
        result = set()
        for x in self.session.GetParameter("PsActiveProcessHead").list_of_type(
                "_EPROCESS", "ActiveProcessLinks"):
            result.add(x.obj_offset)

        self.session.logging.debug(
            "Listed %s processes using PsActiveProcessHead", len(result))

        return result


class PsListCSRSSHook(AbstractWindowsParameterHook):
    name = "pslist_CSRSS"

    def calculate(self):
        """Enumerate processes using the csrss.exe handle table"""
        result = set()

        # First find csrss process using a simpler method.
        for proc_offset in self.session.GetParameter(
                "pslist_PsActiveProcessHead"):
            proc = self.session.profile._EPROCESS(proc_offset)
            if proc.name == "csrss.exe":
                # Gather the handles to process objects
                for handle in proc.ObjectTable.handles():
                    if handle.get_object_type() == "Process":
                        process = handle.dereference_as("_EPROCESS")
                        result.add(process.obj_offset)

        self.session.logging.debug(
            "Listed %s processes using CSRSS", len(result))

        return result


class PsListPspCidTableHook(AbstractWindowsParameterHook):
    name = "pslist_PspCidTable"

    def calculate(self):
        """Enumerate processes by walking the PspCidTable"""
        result = set()

        # Follow the pointers to the table base
        PspCidTable = self.session.profile.get_constant_object(
            "PspCidTable",
            target="Pointer",
            target_args=dict(
                target="_PSP_CID_TABLE"
                )
            )

        # Walk the handle table
        for handle in PspCidTable.handles():
            if handle.get_object_type() == "Process":
                process = handle.dereference_as("_EPROCESS")
                result.add(process.obj_offset)

        self.session.logging.debug(
            "Listed %s processes using PspCidTable", len(result))

        return result


class PsListSessionsHook(AbstractWindowsParameterHook):
    name = "pslist_Sessions"

    def calculate(self):
        """Enumerate processes by walking the SessionProcessLinks"""
        result = set()
        sessions = set()

        # First find unique sessions using a simpler method.
        for proc_offset in self.session.GetParameter(
                "pslist_PsActiveProcessHead"):
            proc = self.session.profile._EPROCESS(proc_offset)
            if proc.Session in sessions:
                continue

            sessions.add(proc.Session)

            # Now enumerate all tasks in session list.
            for task in proc.Session.ProcessList.list_of_type(
                    "_EPROCESS", "SessionProcessLinks"):
                result.add(task.obj_offset)

        self.session.logging.debug(
            "Listed %s processes using Sessions", len(result))

        return result


class PsListHandlesHook(AbstractWindowsParameterHook):
    name = "pslist_Handles"

    def calculate(self):
        """Enumerate processes by walking the SessionProcessLinks"""
        result = set()
        handle_table_list_head = self.session.profile.get_constant_object(
            "HandleTableListHead", "_LIST_ENTRY")

        for table in handle_table_list_head.list_of_type(
                "_HANDLE_TABLE", "HandleTableList"):
            proc = table.QuotaProcess.deref()
            if proc and proc.pid > 0:
                result.add(proc.obj_offset)

        self.session.logging.debug(
            "Listed %s processes using Handles", len(result))


        return result
