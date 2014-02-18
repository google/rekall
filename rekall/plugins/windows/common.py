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

import logging
import re

from rekall import config
from rekall import scan
from rekall import obj
from rekall import kb
from rekall import plugin
from rekall import utils

from rekall.plugins import core


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
            logging.debug("Found _EPROCESS @ 0x%X (DTB: 0x%X)",
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

    def scan_for_process(self):
        """Scan the image for the idle process."""
        for process in WinDTBScanner(
            session=self.session, process_name=self.process_name,
            profile=self.profile,
            address_space=self.physical_address_space).scan():
            yield process

    def dtb_hits(self):
        for eprocess in self.scan_for_process():
            result = eprocess.Pcb.DirectoryTableBase.v()
            if result:
                yield result, eprocess

    def VerifyHit(self, hit):
        """Check the eprocess for sanity."""
        dtb, eprocess = hit
        address_space = self.CreateAS(dtb)

        # In windows the DTB must be page aligned, except for PAE images where
        # its aligned to a 0x20 size.
        if not self.profile.metadata("pae") and address_space.dtb & 0xFFF != 0:
            return

        if self.profile.metadata("pae") and address_space.dtb & 0xF != 0:
            return

        version = self.profile.metadata("major"), self.profile.metadata("minor")
        # The test below does not work on windows 8 with the idle process.
        if version < ("6", "2"):
            # Reflect through the address space at ourselves. Note that the Idle
            # process is not usually in the PsActiveProcessHead list, so we use
            # the ThreadListHead instead.
            list_head = eprocess.ThreadListHead.Flink

            if list_head == 0:
                return

            me = list_head.dereference(vm=address_space).Blink.Flink
            if me.v() != list_head.v():
                return

        self.session.SetParameter("idle_process", eprocess)
        return address_space

    def render(self, renderer):
        renderer.table_header(
            [("_EPROCESS (P)", "physical_eprocess", "[addrpad]"),
             ("DTB", "dtv", "[addrpad]"),
             ("Valid", "valid", "")])

        for dtb, eprocess in self.dtb_hits():
            address_space = self.CreateAS(dtb)

            renderer.table_row(
                eprocess.obj_offset, dtb,
                self.VerifyHit((dtb, eprocess)) is not None)


## The following are checks for pool scanners.

class PoolTagCheck(scan.StringCheck):
    """This scanner checks for the occurrence of a pool tag.

    It is basically a StringCheck but it offsets the check with a constant.
    """
    def __init__(self, tag=None, **kwargs):
        super(PoolTagCheck, self).__init__(needle=tag, **kwargs)

        # The offset from the start of _POOL_HEADER to the tag.
        self.tag_offset = self.profile.get_obj_offset(
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

        self.pool_align = self.profile.constants['PoolAlignment']
        if self.condition is None:
          raise RuntimeError("No pool size provided")

    def check(self, buffer_as, offset):
        pool_hdr = self.profile._POOL_HEADER(
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
        pool_hdr = self.profile._POOL_HEADER(
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
        pool_hdr = self.profile._POOL_HEADER(
            vm=buffer_as, offset=offset)

        return pool_hdr.PoolIndex == self.value


class PoolScanner(scan.BaseScanner):
    """A scanner for pool allocations."""

    # These objects are allocated in the pool allocation.
    allocation = ['_POOL_HEADER']

    def scan(self, offset=0, maxlen=None):
        """Yields instances of _POOL_HEADER which potentially match."""

        maxlen = maxlen or self.profile.get_constant("MaxPointer")
        for hit in super(PoolScanner, self).scan(offset=offset, maxlen=maxlen):
            yield self.profile._POOL_HEADER(vm=self.address_space, offset=hit)


class PoolScannerPlugin(plugin.KernelASMixin, AbstractWindowsCommandPlugin):
    """A base class for all pool scanner plugins."""
    __abstract = True

    @classmethod
    def args(cls, parser):
        super(PoolScannerPlugin, cls).args(parser)
        parser.add_argument(
            "--scan_in_kernel", default=False, action="store_true",
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


class KDBGHook(kb.ParameterHook):
    """A Hook to calculate the KDBG when needed."""

    name = "kdbg"

    def calculate(self):
        # Try to just get the KDBG address using the profile (There is some
        # veriation in the name between WinXP and Win7.
        for name in ["_KdDebuggerDataBlock", "KdDebuggerDataBlock"]:
            kdbg = self.session.profile.get_constant_object(
                name, "_KDDEBUGGER_DATA64",
                vm=self.session.kernel_address_space)

            # Verify it.
            if kdbg.Header.OwnerTag == "KDBG":
                return kdbg

        # Cant find it from the profile, look for it the old way.
        logging.info(
            "KDBG not provided - Rekall will try to "
            "automatically scan for it now using plugin.kdbgscan.")

        for kdbg in self.session.plugins.kdbgscan(
            session=self.session).hits():
            # Just return the first one
            logging.info("Found a KDBG hit %r. Hope it works. If not try "
                         "setting it manually.", kdbg)

            return kdbg


class PsActiveProcessHeadHook(kb.ParameterHook):
    """The PsActiveProcessHead is actually found in the profile symbols."""

    name = "PsActiveProcessHead"

    def calculate(self):
        for name in ["_PsActiveProcessHead", "PsActiveProcessHead"]:
            head = self.session.profile.get_constant_object(
                name, "_LIST_ENTRY",
                vm=self.session.kernel_address_space)

            # Verify it.
            if head.reflect():
                return head

        return head


class KDBGMixin(plugin.KernelASMixin):
    """A plugin mixin to make sure the kdbg is set correctly."""

    _kdbg = None

    @property
    def kdbg(self):
        if self._kdbg is None:
            self._kdbg = self.session.GetParameter("kdbg")

        # Allow kdbg to be an actual object.
        if isinstance(self._kdbg, obj.BaseObject):
            return self._kdbg

        # Or maybe its an integer representing the offset.
        elif self._kdbg:
            self._kdbg = self.profile._KDDEBUGGER_DATA64(
                offset=int(self._kdbg), vm=self.kernel_address_space)

            return self._kdbg

    @kdbg.setter
    def kdbg(self, value):
        self._kdbg = value

    @classmethod
    def args(cls, parser):
        """Declare the command line args we need."""
        super(KDBGMixin, cls).args(parser)
        parser.add_argument("--kdbg", action=config.IntParser,
                            help="Location of the KDBG structure.")

    def __init__(self, kdbg=None, **kwargs):
        """Ensure there is a valid KDBG object.

        Args:
          kdbg: The location of the kernel debugger block (In the physical
             AS).
        """
        super(KDBGMixin, self).__init__(**kwargs)
        self._kdbg = kdbg



class WindowsCommandPlugin(KDBGMixin, AbstractWindowsCommandPlugin):
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
                            action=config.ArrayIntParser, nargs="+",
                            help="Kernel addresses of eprocess structs.")

        parser.add_argument("--phys_eprocess",
                            action=config.ArrayIntParser, nargs="+",
                            help="Physical addresses of eprocess structs.")

        parser.add_argument("--pid",
                            action=config.ArrayIntParser, nargs="+",
                            help="One or more pids of processes to select.")

        parser.add_argument("--proc_regex", default=None,
                            help="A regex to select a process by name.")

        parser.add_argument("--eprocess_head", action=config.IntParser,
                            help="Use this as the process head. If "
                            "specified we do not use kdbg.")

    def __init__(self, eprocess=None, phys_eprocess=None, pid=None,
                 proc_regex=None, eprocess_head=None, **kwargs):
        """Filters processes by parameters.

        Args:
           physical_eprocess: One or more EPROCESS structs or offsets defined in
              the physical AS.

           pid: A single pid.

           proc_regex: A regular expression for filtering process name (using
             _EPROCESS.ImageFileName).

           eprocess_head: Use this as the start of the process listing (in case
             PsActiveProcessHead is missing).
        """
        super(WinProcessFilter, self).__init__(**kwargs)

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

        self.phys_eprocess = phys_eprocess
        self.eprocess = eprocess

        pids = []
        if isinstance(pid, list):
            pids.extend(pid)

        elif isinstance(pid, (int, long)):
            pids.append(pid)

        if self.session.pid and not pid:
            pids.append(self.session.pid)

        self.pids = pids
        self.proc_regex_text = proc_regex
        if isinstance(proc_regex, basestring):
            proc_regex = re.compile(proc_regex, re.I)

        self.proc_regex = proc_regex
        self.eprocess_head = eprocess_head

        # Sometimes its important to know if any filtering is specified at all.
        self.filtering_requested = (self.pids or self.proc_regex or
                                    self.phys_eprocess or self.eprocess)

    def filter_processes(self):
        """Filters eprocess list using phys_eprocess and pids lists."""
        # No filtering required:
        if not self.filtering_requested:
            for eprocess in self.session.plugins.pslist(
                session=self.session, kdbg=self._kdbg,
                eprocess_head=self.eprocess_head).list_eprocess():
                yield eprocess
        else:
            # We need to filter by phys_eprocess
            for offset in self.phys_eprocess:
                yield self.virtual_process_from_physical_offset(offset)

            for offset in self.eprocess:
                yield self.profile._EPROCESS(vm=self.kernel_address_space,
                                             offset=int(offset))

            # We need to filter by pids
            for eprocess in self.session.plugins.pslist(
                session=self.session, kdbg=self._kdbg,
                eprocess_head=self.eprocess_head).list_eprocess():
                if int(eprocess.UniqueProcessId) in self.pids:
                    yield eprocess
                elif self.proc_regex and self.proc_regex.match(
                    utils.SmartUnicode(eprocess.ImageFileName)):
                    yield eprocess


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
            vm=self.kernel_address_space.base)

        # We cast our list entry in the kernel AS by following Flink into the
        # kernel AS and then the Blink. Note the address space switch upon
        # dereferencing the pointer.
        our_list_entry = physical_eprocess.ActiveProcessLinks.Flink.dereference(
            vm=self.kernel_address_space).Blink.dereference()

        # Now we get the EPROCESS object from the list entry.
        return our_list_entry.dereference_as("_EPROCESS", "ActiveProcessLinks")
