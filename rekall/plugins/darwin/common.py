# Rekall Memory Forensics
#
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

# The code in this directory is based on original code and algorithms by Andrew
# Case (atcuno@gmail.com).
__author__ = "Michael Cohen <scudette@google.com>"

import logging
import re

from rekall import args
from rekall import obj
from rekall import plugin
from rekall import scan
from rekall import utils

from rekall.plugins import core
from rekall.plugins.addrspaces import amd64

LOW_4GB_MASK = 0x00000000FFFFFFFF

def ID_MAP_VTOP(x):
    return x & LOW_4GB_MASK


class AbstractDarwinCommandPlugin(plugin.PhysicalASMixin,
                                  plugin.ProfileCommand):
    """A base class for all darwin based plugins."""
    __abstract = True

    @classmethod
    def is_active(cls, config):
        """We are only active if the profile is darwin."""
        return (getattr(config.profile, "_md_os", None) == 'darwin' and
                plugin.Command.is_active(config))


class CatfishScanner(scan.BaseScanner):
    checks = [
        ("StringCheck", dict(needle="Catfish \x00\x00"))
        ]


class DarwinFindKSLR(AbstractDarwinCommandPlugin):
    """A scanner for KSLR slide values in the Darwin kernel.

    The scanner works by looking up a known data structure and comparing
    its actual location to its expected location. Verification is a similar
    process, using a second constant. This takes advantage of the fact that both
    data structures are in a region of kernel memory that maps to the physical
    memory in a predictable way (see ID_MAP_VTOP).

    Human-readable output includes values of the kernel version string (which is
    used for validation) for manual review, in case there are false positives.
    """

    __name = "find_kslr"

    @classmethod
    def is_active(cls, config):
        return (super(DarwinFindKSLR, cls).is_active(config) and
                config.profile.get_constant("_BootPML4"))

    def vm_kernel_slide_hits(self):
        """Tries to compute the KSLR slide.

        In an ideal scenario, this should return exactly one valid result.

        Yields:
          (int) semi-validated KSLR value
        """

        expected_offset = self.profile.get_constant("_lowGlo",
                                                    is_address=False)
        expected_offset = ID_MAP_VTOP(expected_offset)

        for hit in CatfishScanner(
            address_space=self.physical_address_space,
            session=self.session).scan():
            vm_kernel_slide = int(hit - expected_offset)

            if self._validate_vm_kernel_slide(vm_kernel_slide):
                yield vm_kernel_slide

    def vm_kernel_slide(self):
        """Returns the first result of vm_kernel_slide hits and stops the scan.

        This is the idiomatic way of using this plugin if all you need is the
        likely KSLR slide value.

        Returns:
          A value for the KSLR slide that appears sane.
        """
        for vm_kernel_slide in self.vm_kernel_slide_hits():
            return vm_kernel_slide

    def _lookup_version_string(self, vm_kernel_slide):
        """Uses vm_kernel_slide to look up kernel version string.

        This is used for validation only. Physical address space is
        asumed to map to kernel virtual address space as expressed by
        ID_MAP_VTOP.

        Args:
          vm_kernel_slide: KSLR slide to be used for lookup. Overrides whatever
          may already be set in session.

        Returns:
          Kernel version string (should start with "Dawrin Kernel"
        """
        version_offset = self.profile.get_constant("_version",
                                                   is_address=False)
        version_offset += vm_kernel_slide
        version_offset = ID_MAP_VTOP(version_offset)

        return self.profile.String(vm=self.physical_address_space,
                                   offset=version_offset)

    def _validate_vm_kernel_slide(self, vm_kernel_slide):
        """Checks sanity of vm_kernel_slide by looking up kernel version.
        If the result a string that looks like the kernel version string the
        slide value is assumed to be valid. Note that this can theoretically
        give false positives.

        Args:
          vm_kernel_slide: KSLR slide to be used for validation. Overrides
          whatever may already be set in session.

        Returns:
          True if vm_kernel_slide value appears sane. False otherwise.
        """
        version_string = self._lookup_version_string(vm_kernel_slide)
        return version_string[0:13] == "Darwin Kernel"

    def render(self, renderer):
        renderer.table_header([
            ("KSLR Slide", "vm_kernel_slide", "[addrpad]"),
            ("Kernel Version", "_version", "30"),
        ])

        for vm_kernel_slide in self.vm_kernel_slide_hits():
            renderer.table_row(vm_kernel_slide,
                               self._lookup_version_string(vm_kernel_slide))


class DarwinFindDTB(AbstractDarwinCommandPlugin):
    """A scanner for DTB values on the Darwin kernel.

    For darwin, the dtb values are taken directly from the symbol file.

    This one plugin handles both 32 and 64 bits.
    """

    __name = "find_dtb"

    def dtb_hits(self):
        """Tries to locate the DTB."""
        if self.profile.get_constant("_BootPML4"):
            return self._dtb_hits_m_lion()
        else:
            return self._dtb_hits_pre_m_lion()

    def _dtb_hits_pre_m_lion(self):
        if self.profile.metadata("memory_model") == "32bit":
            result = self.profile.get_constant("_IdlePDPT")

            # Since the DTB must be page aligned, if this is not, it is probably
            # a pointer to the real DTB.
            if result % 0x1000:
                result = self.profile.get_constant_object(
                    "_IdlePDPT", "unsigned int")

            yield result, None
        else:
            result = self.profile.get_constant("_IdlePML4")
            if result > 0xffffff8000000000:
                result -= 0xffffff8000000000

            yield result, None

    def _dtb_hits_m_lion(self):
        """Get DTB on Mountain Lion kernels.

        From 10.8 Onwards, OSX implements Kernsl ASLR as described here:
        http://essay.utwente.nl/62852/1/Thesis_Daan_Keuper.pdf (3.4).

        This essentially addes a constant vm_kernel_slide to all kernel
        addresses:

        http://www.opensource.apple.com/source/xnu/xnu-2422.1.72/osfmk/mach/vm_param.h

        The Catfish trick is very similar to how we find KDBG on windows. There
        is a known signature for the lowGlo struct which we can find in memory,
        but there is also an exported symbol for this. The difference is
        therefore the slide value (vm_kernel_slide).

        http://www.opensource.apple.com/source/xnu/xnu-2422.1.72/osfmk/x86_64/lowmem_vectors.c

        lowglo lowGlo __attribute__ ((aligned(PAGE_SIZE))) = {
           .lgVerCode= { 'C','a','t','f','i','s','h',' ' },
        ....

        Note that we also allow the user to specify vm_kernel_slide in the
        session.

        #define LOW_4GB_MASK((vm_offset_t)0x00000000FFFFFFFFUL)

        At xnu-2422.1.72/osfmk/i386/pmap.h:
        #define ID_MAP_VTOP(x) ((void *)(((uint64_t)(x)) & LOW_4GB_MASK))

        xnu-2422.1.72/osfmk/x86_64/pmap.c:
        kernel_pmap->pm_cr3 = (uintptr_t)ID_MAP_VTOP(IdlePML4);

        """
        lowGlo = ID_MAP_VTOP(self.profile.get_constant("_lowGlo"))
        vm_kernel_slide = self.session.GetParameter("vm_kernel_slide")
        if vm_kernel_slide is None:
            for hit in CatfishScanner(
                address_space=self.physical_address_space,
                session=self.session).scan():

                # From this point on, the profile will automatically slide
                # constants by this amount.
                vm_kernel_slide = hit - lowGlo
                self.session.StoreParameter(
                    "vm_kernel_slide", int(vm_kernel_slide))

                bootpml4 = ID_MAP_VTOP(self.profile.get_constant("_BootPML4"))
                boot_as = amd64.AMD64PagedMemory(
                    base=self.physical_address_space, dtb=bootpml4)

                idlepml4_addr = ID_MAP_VTOP(
                    self.profile.get_constant("_IdlePML4"))

                idlepml4 = self.profile.Object(
                    "unsigned int", offset=idlepml4_addr, vm=boot_as)

                if idlepml4:
                    yield idlepml4, None

    def verify_address_space(self, address_space=None, **_):
        # Check the os version symbol using this address space.
        return "Darwin" == self.profile.get_constant_object(
            "_version",
            target="String",
            target_args=dict(length=6),
            vm=address_space)

    def render(self, renderer):
        renderer.table_header([("DTB", "dtv", "[addrpad]"),
                               ("Valid", "valid", "")])

        for dtb, _ in self.dtb_hits():
            address_space = core.GetAddressSpaceImplementation(self.profile)(
                session=self.session, base=self.physical_address_space, dtb=dtb)

            renderer.table_row(
                dtb, self.verify_address_space(address_space=address_space))


class DarwinPlugin(plugin.KernelASMixin, AbstractDarwinCommandPlugin):
    """Plugin which requires the kernel Address space to be loaded."""
    __abstract = True


class DarwinProcessFilter(DarwinPlugin):
    """A class for filtering processes."""

    __abstract = True

    @classmethod
    def args(cls, parser):
        super(DarwinProcessFilter, cls).args(parser)
        parser.add_argument("--pid",
                            action=args.ArrayIntParser, nargs="+",
                            help="One or more pids of processes to select.")

        parser.add_argument("--proc_regex", default=None,
                            help="A regex to select a process by name.")

        parser.add_argument("--phys_proc",
                            action=args.ArrayIntParser, nargs="+",
                            help="Physical addresses of proc structs.")

        parser.add_argument("--proc", action=args.ArrayIntParser, nargs="+",
                            help="Kernel addresses of proc structs.")

        parser.add_argument("--first", action=args.IntParser,
                            help="Kernel addresses of first proc to start "
                            "following.")

        parser.add_argument(
            "--method", choices=cls.METHODS, nargs="+",
            help="Method to list processes (Default uses all methods).")


    def __init__(self, pid=None, proc_regex=None, phys_proc=None, proc=None,
                 first=None, method=None, **kwargs):
        """Filters processes by parameters.

        Args:
           phys_proc_struct: One or more proc structs or offsets defined in
              the physical AS.

           pids: A list of pids.
           pid: A single pid.
        """
        super(DarwinProcessFilter, self).__init__(**kwargs)
        self.methods = method or self.METHODS

        if isinstance(phys_proc, (int, long)):
            phys_proc = [phys_proc]
        elif phys_proc is None:
            phys_proc = []

        if isinstance(proc, (int, long)):
            proc = [proc]
        elif isinstance(proc, obj.Struct):
            proc = [proc.obj_offset]
        elif proc is None:
            proc = []

        self.phys_proc = phys_proc
        self.proc = proc

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

        # Without a specified proc head, we use the proclist from _allproc
        # constant.
        if not first:
            first = self.profile.get_constant_object(
                "_allproc", target="proclist").lh_first

        self.first = first

        # Sometimes its important to know if any filtering is specified at all.
        self.filtering_requested = (self.pids or self.proc_regex or
                                    self.phys_proc or self.proc)

    def list_using_allproc(self):
        """List all processes by following the _allproc list head."""
        result = set(self.first.p_list)
        return result

    def list_using_tasks(self):
        """List processes using the processor tasks queue.


        See
        /osfmk/kern/processor.c (processor_set_things)
        """
        seen = set()

        tasks = self.profile.get_constant_object(
            "_tasks",
            target="queue_entry",
            vm=self.kernel_address_space)

        for task in tasks.list_of_type("task", "tasks"):
            proc = task.bsd_info.deref()
            if proc:
                seen.add(proc)

        return seen

    def list_using_pgrp_hash(self):
        """Process groups are organized in a hash chain.

        xnu-1699.26.8/bsd/sys/proc_internal.h
        """
        seen = set()

        # Note that _pgrphash is initialized through:

        # xnu-1699.26.8/bsd/kern/kern_proc.c:195
        # hashinit(int elements, int type, u_long *hashmask)

        # /xnu-1699.26.8/bsd/kern/kern_subr.c: 327
        # hashinit(int elements, int type, u_long *hashmask) {
        #    ...
        # *hashmask = hashsize - 1;

        # Hence the value in _pgrphash is one less than the size of the hash
        # table.
        pgr_hash_table = self.profile.get_constant_object(
            "_pgrphashtbl",
            target="Pointer",
            target_args=dict(
                target="Array",
                target_args=dict(
                    target="pgrphashhead",
                    count=self.profile.get_constant_object(
                        "_pgrphash", "unsigned long") + 1
                    )
                )
            )

        for slot in pgr_hash_table.deref():
            for pgrp in slot.lh_first.walk_list("pg_hash.le_next"):
                for proc in pgrp.pg_members.lh_first.walk_list(
                    "p_pglist.le_next"):
                    seen.add(proc)

        return seen

    def list_using_pid_hash(self):
        """Lists processes using pid hash tables.

        xnu-1699.26.8/bsd/kern/kern_proc.c:834:
        pfind_locked(pid_t pid)
        """
        seen = set()

        # Note that _pidhash is initialized through:

        # xnu-1699.26.8/bsd/kern/kern_proc.c:194
        # pidhashtbl = hashinit(maxproc / 4, M_PROC, &pidhash);

        # /xnu-1699.26.8/bsd/kern/kern_subr.c: 327
        # hashinit(int elements, int type, u_long *hashmask) {
        #    ...
        # *hashmask = hashsize - 1;

        # Hence the value in pidhash is one less than the size of the hash
        # table.
        pid_hash_table = self.profile.get_constant_object(
            "_pidhashtbl",
            target="Pointer",
            target_args=dict(
                target="Array",
                target_args=dict(
                    target="pidhashhead",
                    count=self.profile.get_constant_object(
                        "_pidhash", "unsigned long") + 1
                    )
                )
            )

        for plist in pid_hash_table.deref():
            for proc in plist.lh_first.walk_list("p_hash.le_next"):
                if proc:
                    seen.add(proc)

        return seen

    def list_procs(self):
        """Uses a few methods to list the procs."""
        seen = set()

        for k, handler in self.METHODS.items():
            if k in self.methods:
                result = handler(self)
                logging.debug("Listed %s processes using %s", len(result), k)
                seen.update(result)

        # Sort by pid so that the output ordering remains stable.
        return sorted(seen, key=lambda x: x.p_pid)

    def filter_processes(self):
        """Filters proc list using phys_proc and pids lists."""
        # No filtering required:
        if not self.filtering_requested:
            for proc in self.list_procs():
                yield proc
        else:
            # We need to filter by phys_proc
            for offset in self.phys_proc:
                yield self.virtual_process_from_physical_offset(offset)

            for offset in self.proc:
                yield self.profile.proc(vm=self.kernel_address_space,
                                        offset=int(offset))

            # We need to filter by pids
            for proc in self.list_procs():
                if int(proc.p_pid) in self.pids:
                    yield proc

                elif self.proc_regex and self.proc_regex.match(
                    utils.SmartUnicode(proc.p_comm)):
                    yield proc


    def virtual_process_from_physical_offset(self, physical_offset):
        """Tries to return an proc in virtual space from a physical offset.

        We do this by reflecting off the list elements.

        Args:
           physical_offset: The physcial offset of the process.

        Returns:
           an _PROC object or a NoneObject on failure.
        """
        physical_proc = self.profile.eprocess(offset=int(physical_offset),
                                              vm=self.kernel_address_space.base)

        # We cast our list entry in the kernel AS by following Flink into the
        # kernel AS and then the Blink. Note the address space switch upon
        # dereferencing the pointer.
        our_list_entry = physical_proc.procs.next.dereference(
            vm=self.kernel_address_space).prev.dereference()

        # Now we get the proc_struct object from the list entry.
        return our_list_entry.dereference_as("proc_struct", "procs")


    METHODS = {
        "allproc": list_using_allproc,
        "tasks": list_using_tasks,
        "pgrphash": list_using_pgrp_hash,
        "pidhash": list_using_pid_hash,
        }



class HeapScannerMixIn(object):
    """A mixin for converting a scanner into a heap only scanner."""
    def scan(self, **_):
        for vma in self.task.mm.mmap.walk_list("vm_next"):
            # Only use the vmas inside the heap area.
            if (vma.vm_start >= self.task.mm.start_brk or
                vma.vm_end <= self.task.mm.brk):
                for hit in super(HeapScannerMixIn, self).scan(
                    offset=vma.vm_start, maxlen=vma.vm_end-vma.vm_start):
                    yield hit


class KernelAddressCheckerMixIn(object):
    """A plugin mixin which does kernel address checks."""

    def __init__(self, **kwargs):
        super(KernelAddressCheckerMixIn, self).__init__(**kwargs)

        # We use the module plugin to help us local addresses inside kernel
        # modules.
        self.module_plugin = self.session.plugins.lsmod(session=self.session)
