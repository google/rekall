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

# Disabled because pylint is wrong about it pretty much all the time.
# pylint: disable=abstract-method


from rekall import kb
from rekall import plugin
from rekall import scan
from rekall import utils

from rekall.plugins import core

# A few notes on XNU's (64bit) memory layout:
#
# Because of the way the Darwin kernel (XNU) is bootstrapped, a section of its
# virtual address space maps linearly to the base of the physical address space.
# This relationship is basically:
# KERNEL_MIN_ADDRESS + the_physical_address = the_virtual_address
#
# The kernel ensures this when allocating certain data structures, most notably
# the page tables [1]. However, the kernel doesn't actually "know" the value of
# KERNEL_MIN_ADDRESS, which is defined the Makefile [2]. Instead, allocations
# are done by keeping a cursor at the lowest available physical address [3].
#
# Because of this, when the kernel needs to convert an address from the virtual
# address space to the physical address space without relying on the page
# tables, it uses a "safer" variation on the above rule and masks out the first
# 32 bits of the address using a macro called ID_MAP_VTOP [4,5], which is a
# simple bitmask (LOW_4GB_MASK [6]).
#
# We copy/adapt all three #defines below. When we need to bootstrap the virtual
# address space, relying on ID_MAP_VTOP is preferrable, because it's less
# fragile. However, KERNEL_MIN_ADDRESS can be a good heuristic for deciding
# whether a particular value is a valid pointer in the kernel virtual address
# space, so I decided to keep it around.
#
# [1]
# github.com/opensource-apple/xnu/blob/10.9/osfmk/i386/i386_init.c#L134
#
# [2]
# github.com/opensource-apple/xnu/blob/10.9/makedefs/MakeInc.def#L258
#
# [3] This is where physfree is defined as the next free page, after a blank
# page, after the last page of the kernel image as determined by the bootloader.
# github.com/opensource-apple/xnu/blob/10.9/osfmk/i386/i386_init.c#L330
#
# [4]
# github.com/opensource-apple/xnu/blob/10.9/osfmk/i386/pmap.h#L353
#
# [5] Example use, to set the physical address of the DTB when switching address
# spaces, knowing the virtual address of the first page table:
# github.com/opensource-apple/xnu/blob/10.9/osfmk/i386/pal_routines.c#L254
#
# [6]
# github.com/opensource-apple/xnu/blob/10.9/osfmk/i386/pmap.h#L119
LOW_4GB_MASK = 0x00000000ffffffff
KERNEL_MIN_ADDRESS = 0xffffff8000000000


def ID_MAP_VTOP(x):
    return x & LOW_4GB_MASK

# On x64, only 48 bits of the pointer are addressable.
X64_POINTER_MASK = 0x0000ffffffffffff


class DarwinOnlyMixin(object):
    """Every Darwin-only plugin or hook will have this mixin in their MRO."""

    mode = "mode_darwin_memory"


class AbstractDarwinParameterHook(DarwinOnlyMixin, kb.ParameterHook):
    """Base class for session parameter hooks on Darwin."""
    __abstract = True


class AbstractDarwinCommand(DarwinOnlyMixin,
                            plugin.KernelASMixin,
                            plugin.PhysicalASMixin,
                            plugin.TypedProfileCommand,
                            plugin.ProfileCommand):
    """Base class for Darwin profile commands."""
    __abstract = True


class AbstractDarwinProducer(plugin.Producer,
                             AbstractDarwinCommand):
    """Base class for Darwin producers using the physical AS."""
    __abstract = True


class AbstractDarwinCachedProducer(plugin.CachedProducer,
                                   AbstractDarwinCommand):
    """Base class for Darwin producers backed by a session param hook."""
    __abstract = True


class KernelSlideHook(AbstractDarwinParameterHook):
    """Find the kernel slide if needed."""

    name = "vm_kernel_slide"

    def calculate(self):
        if self.session.GetParameter("mode_darwin_mountain_lion_plus"):
            return DarwinFindKASLR(session=self.session).vm_kernel_slide()

        # Kernel slide should be treated as 0 if not relevant.
        return 0


class CatfishScanner(scan.BaseScanner):
    checks = [
        ("StringCheck", dict(needle="Catfish \x00\x00"))
    ]


class CatfishOffsetHook(AbstractDarwinParameterHook):
    """Find the actual offset of the _lowGlo struct."""

    name = "catfish_offset"

    def calculate(self):
        limit = self.session.GetParameter(
            "autodetect_scan_length", 10*1024*1024*1024)

        for hit in CatfishScanner(
                address_space=self.session.physical_address_space,
                session=self.session).scan(0, maxlen=limit):
            return hit


class DarwinKASLRMixin(object):
    """Ensures that KASLR slide is computed and stored in the session."""

    @classmethod
    def args(cls, parser):
        super(DarwinKASLRMixin, cls).args(parser)

        parser.add_argument("--vm_kernel_slide", type="IntParser",
                            help="OS X 10.8 and later: kernel ASLR slide.")

    def __init__(self, vm_kernel_slide=None, **kwargs):
        """A mixin for Darwin plugins that require a valid KASLR slide.

        Args:
          vm_kernel_slide: The integer KASLR slide used in this image. If not
          given it will be computed.
        """
        super(DarwinKASLRMixin, self).__init__(**kwargs)

        if not self.session.GetParameter("mode_darwin_mountain_lion_plus"):
            return

        if vm_kernel_slide is not None:
            self.session.SetCache("vm_kernel_slide", vm_kernel_slide)


class DarwinFindKASLR(plugin.PhysicalASMixin, DarwinOnlyMixin,
                      plugin.ProfileCommand):
    """A scanner for KASLR slide values in the Darwin kernel.

    The scanner works by looking up a known data structure and comparing
    its actual location to its expected location. Verification is a similar
    process, using a second constant. This takes advantage of the fact that both
    data structures are in a region of kernel memory that maps to the physical
    memory in a predictable way (see ID_MAP_VTOP).

    Human-readable output includes values of the kernel version string (which is
    used for validation) for manual review, in case there are false positives.
    """

    name = "find_kaslr"
    mode = "mode_darwin_mountain_lion_plus"

    def all_catfish_hits(self):
        """Yields possible lowGlo offsets, starting with session-cached one.

        Because the first hit on the catfish string isn't necessarily the right
        one, this function will yield subsequent ones by scanning the physical
        address space, starting with the offset of the cached first hit.

        The caller is responsible for updating the session cache with the
        correct offset.
        """
        first_hit = self.session.GetParameter("catfish_offset")
        yield first_hit

        maxlen = self.session.GetParameter("autodetect_scan_length")
        for hit in CatfishScanner(
                address_space=self.session.physical_address_space,
                session=self.session).scan(offset=first_hit + 1,
                                           maxlen=maxlen):
            yield hit

    def vm_kernel_slide_hits(self):
        """Tries to compute the KASLR slide.

        In an ideal scenario, this should return exactly one valid result.

        Yields:
          (int) semi-validated KASLR value
        """

        expected_offset = self.profile.get_constant(
            "_lowGlo", is_address=False)
        expected_offset = ID_MAP_VTOP(expected_offset)

        for hit in self.all_catfish_hits():
            vm_kernel_slide = int(hit - expected_offset)

            if self._validate_vm_kernel_slide(vm_kernel_slide):
                self.session.SetCache("catfish_offset", hit)
                yield vm_kernel_slide

    def vm_kernel_slide(self):
        """Returns the first result of vm_kernel_slide hits and stops the scan.

        This is the idiomatic way of using this plugin if all you need is the
        likely KASLR slide value.

        Returns:
          A value for the KASLR slide that appears sane.
        """
        self.session.logging.debug("Searching for KASLR hits.")
        for vm_kernel_slide in self.vm_kernel_slide_hits():
            return vm_kernel_slide

    def _lookup_version_string(self, vm_kernel_slide):
        """Uses vm_kernel_slide to look up kernel version string.

        This is used for validation only. Physical address space is
        asumed to map to kernel virtual address space as expressed by
        ID_MAP_VTOP.

        Args:
          vm_kernel_slide: KASLR slide to be used for lookup. Overrides whatever
          may already be set in session.

        Returns:
          Kernel version string (should start with "Darwin Kernel"
        """
        version_offset = self.profile.get_constant(
            "_version", is_address=False)
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
          vm_kernel_slide: KASLR slide to be used for validation. Overrides
          whatever may already be set in session.

        Returns:
          True if vm_kernel_slide value appears sane. False otherwise.
        """
        version_string = self._lookup_version_string(vm_kernel_slide)
        return version_string[0:13] == "Darwin Kernel"

    def render(self, renderer):
        renderer.table_header([
            ("KASLR Slide", "vm_kernel_slide", "[addrpad]"),
            ("Kernel Version", "_version", "30"),
        ])

        for vm_kernel_slide in self.vm_kernel_slide_hits():
            renderer.table_row(vm_kernel_slide,
                               self._lookup_version_string(vm_kernel_slide))


class DarwinFindDTB(DarwinKASLRMixin, DarwinOnlyMixin, core.FindDTB):
    """Tries to find the DTB address for the Darwin/XNU kernel.

    As the XNU kernel developed over the years, the best way of deriving this
    information changed. This class now offers multiple methods of finding the
    DTB. Calling find_dtb should automatically select the best method for the
    job, based on the profile. It will also attempt to fall back on less ideal
    ways of getting the DTB if the best way fails.
    """

    __name = "find_dtb"

    def _dtb_hits_idlepml4(self):
        """On 10.8 and later, x64, tries to determine the DTB using IdlePML4.

        IdlePML4 is the address (in Kernel AS) of the kernel DTB [1]. The DTB
        itself happens to be located in a section of kernel memory that sits at
        the base of the physical address space [2], and its virtual address can
        be converted to its physical address using the ID_MAP_VTOP macro
        which kernel defines for this express purpose [3].

        Should work on: 10.8 and later.
        Best for: 10.9 and later.

        Yields:
          The physical address of the DTB, not verified.

        1:
        github.com/opensource-apple/xnu/blob/10.9/osfmk/i386/i386_init.c#L281

        Here the kernel initializes the page register at the address IdlePML4
        points to (masked using the bitmask macro). The same function switches
        to the newly initialized address space right before returning.

        // IdlePML4 single entry for kernel space.
        fillkpt(IdlePML4 + KERNEL_PML4_INDEX,
                INTEL_PTE_WRITE, (uintptr_t)ID_MAP_VTOP(IdlePDPT), 0, 1);

        2:
        The first page of IdlePML4 is allocated by the ALLOCPAGES function
        located here:
        github.com/opensource-apple/xnu/blob/10.9/osfmk/i386/i386_init.c#L134

        3:
        ID_MAP_VTOP is defined here, as simple bitmask:
        github.com/opensource-apple/xnu/blob/10.9/osfmk/i386/pmap.h#L353
        """
        idlepml4 = ID_MAP_VTOP(self.profile.get_constant(
            "_IdlePML4", True))
        dtb = self.profile.Object("unsigned int", offset=idlepml4,
                                  vm=self.physical_address_space)
        yield int(dtb)

    def _dtb_hits_legacy(self):
        """The original way of getting the DTB, adapted from Volatility.

        I have no idea how or why this is intended to work, but it seems to for
        old images.

        Should work on: 10.7 and earlier.

        Yields:
          The physical address of the DTB, not verified.
        """
        if self.profile.metadata("arch") == "I386":
            result = self.profile.get_constant("_IdlePDPT")

            # Since the DTB must be page aligned, if this is not, it is probably
            # a pointer to the real DTB.
            if result % 0x1000:
                result = self.profile.get_constant_object(
                    "_IdlePDPT", "unsigned int")

            yield result
        else:
            result = self.profile.get_constant("_IdlePML4", is_address=True)
            if result > 0xffffff8000000000:
                result -= 0xffffff8000000000

            yield result

    def _dtb_hits_kernel_pmap(self):
        """On 64-bit systems, finds the DTB from the kernel pmap struct.

        This is a very easy way of getting the DTB on systems where the kernel
        pmap is a static symbol (which seems to be most of them.)

        Yields:
          The physical address of the DTB, not verified.
        """
        kernel_pmap_addr = self.profile.get_constant(
            "_kernel_pmap_store", is_address=True)
        kernel_pmap = self.profile.pmap(offset=ID_MAP_VTOP(kernel_pmap_addr),
                                        vm=self.physical_address_space)
        yield int(kernel_pmap.pm_cr3)

    def _dtb_methods(self):
        """Determines viable methods of getting the DTB based on profile.

        Yields:
          Callable object that will yield DTB values.
        """
        if self.session.GetParameter("mode_darwin_mountain_lion_plus"):
            yield self._dtb_hits_idlepml4
        else:
            yield self._dtb_hits_legacy

        if self.profile.metadata("arch") == "AMD64":
            yield self._dtb_hits_kernel_pmap

    def dtb_hits(self):
        for method in self._dtb_methods():
            for dtb_hit in method():
                yield dtb_hit

    def VerifyHit(self, hit):
        address_space = self.CreateAS(hit)

        if address_space:
            address = self.profile.get_constant(
                "_version", is_address=True)
            if not address_space.is_valid_address(address):
                return

            if address_space.read(address, 13) != "Darwin Kernel":
                return

            return address_space

    def render(self, renderer):
        renderer.table_header([("DTB", "dtb", "[addrpad]"),
                               ("Verified", "verified", "8"),
                               ("Source", "method", "15")])
        for method in self._dtb_methods():
            for dtb_hit in method():
                renderer.table_row(
                    dtb_hit,
                    self.VerifyHit(dtb_hit) is not None,
                    method.__name__)


class ProcessFilterMixin(object):
    """Adds methods and arguments that enable easy fitlering by process."""

    __args = [
        dict(name="pids", type="ArrayIntParser", positional=True,
             help="One or more pids of processes to select."),

        dict(name="proc_regex", type="RegEx",
             help="A regex to select a process by name."),

        dict(name="proc", type="ArrayIntParser",
             help="Kernel addresses of proc structs."),
    ]

    @classmethod
    def methods(cls):
        """Return the names of available proc enumeration methods."""
        # Find all the producers that collect procs and inherit from
        # AbstractDarwinCachedProducer.
        methods = []
        for subclass in AbstractDarwinCachedProducer.classes.itervalues():
            if (issubclass(subclass, AbstractDarwinCachedProducer)
                    and subclass.type_name == "proc"):
                methods.append(subclass.name)
        methods.sort()

        return methods

    @utils.safe_property
    def filtering_requested(self):
        return (self.plugin_args.pids or self.plugin_args.proc_regex or
                self.plugin_args.eprocess)

    def filter_processes(self):
        """Filters proc list using phys_proc and pids lists."""
        # No filtering required:
        procs = sorted(self.session.plugins.collect("proc"),
                       key=lambda proc: proc.pid)

        if not self.filtering_requested:
            for proc in procs:
                yield proc
        else:
            for offset in self.plugin_args.proc:
                yield self.profile.proc(vm=self.kernel_address_space,
                                        offset=int(offset))

            # We need to filter by pids
            for proc in procs:
                if int(proc.p_pid) in self.plugin_args.pids:
                    yield proc

                elif (self.plugin_args.proc_regex and
                      self.plugin_args.proc_regex.match(
                          utils.SmartUnicode(proc.p_comm))):
                    yield proc

    def virtual_process_from_physical_offset(self, physical_offset):
        """Tries to return an proc in virtual space from a physical offset.

        We do this by reflecting off the list elements.

        Args:
           physical_offset: The physcial offset of the process.

        Returns:
           A proc object or a NoneObject on failure.
        """
        physical_proc = self.profile.proc(offset=int(physical_offset),
                                          vm=self.kernel_address_space.base)

        # We cast our list entry in the kernel AS by following Flink into the
        # kernel AS and then the Blink. Note the address space switch upon
        # dereferencing the pointer.
        our_list_entry = physical_proc.procs.next.dereference(
            vm=self.kernel_address_space).prev.dereference()

        # Now we get the proc_struct object from the list entry.
        return our_list_entry.dereference_as("proc_struct", "procs")


class KernelAddressCheckerMixIn(object):
    """A plugin mixin which does kernel address checks."""

    def __init__(self, **kwargs):
        super(KernelAddressCheckerMixIn, self).__init__(**kwargs)

        # We use the module plugin to help us local addresses inside kernel
        # modules.
        self.module_plugin = self.session.plugins.lsmod(session=self.session)
