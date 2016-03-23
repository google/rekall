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

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0 or later
@contact:      atcuno@gmail.com
@organization: Digital Forensics Solutions
"""
import re

from rekall import addrspace
from rekall import kb
from rekall import obj
from rekall import plugin
from rekall import utils

from rekall.plugins import core


class AbstractLinuxCommandPlugin(plugin.PhysicalASMixin,
                                 plugin.ProfileCommand):
    """A base class for all linux based plugins."""
    __abstract = True

    @classmethod
    def is_active(cls, session):
        """We are only active if the profile is linux."""
        return (session.profile.metadata("os") == 'linux' and
                plugin.Command.is_active(session))


class AbstractLinuxParameterHook(kb.ParameterHook):

    @classmethod
    def is_active(cls, session):
        """We are only active if the profile is Linux."""
        return (super(AbstractLinuxParameterHook, cls).is_active(session) and
                session.profile.metadata("os") == 'linux')


class LinuxTestMixin(object):

    @classmethod
    def is_active(cls, session):
        """We are only active if the profile is linux."""
        return (session.profile.metadata("os") == 'linux' and
                plugin.Command.is_active(session))


class LinuxFindDTB(AbstractLinuxCommandPlugin, core.FindDTB):
    """A scanner for DTB values. Handles both 32 and 64 bits.

    The plugin also autodetects when the guest is running as a XEN
    ParaVirtualized guest and returns a compatible address space.
    """

    __name = "find_dtb"

    def VerifyHit(self, dtb):
        """Returns a valid address_space if the dtb is valid."""
        address_space = super(LinuxFindDTB, self).VerifyHit(dtb)
        if address_space:
            # Try to verify the profile by checking the linux_proc_banner.
            # This is to discard kernel version strings found in memory we may
            # know about but that don't really work with the current image.
            linux_banner = address_space.session.profile.get_constant_object(
                "linux_proc_banner", "String", vm=address_space)
            if unicode(linux_banner).startswith(u"%s version %s"):
                return address_space

            self.session.logging.debug("Failed to verify dtb @ %#x" % dtb)

    def GetAddressSpaceImplementation(self):
        """Returns the correct address space class for this profile."""
        # The virtual address space implementation is chosen by the profile.
        architecture = self.profile.metadata("arch")
        if architecture == "AMD64":

            # XEN PV guests have a mapping in p2m_top. We verify this symbol
            # is not NULL.
            pv_info_virt = self.profile.get_constant("pv_info")

            if pv_info_virt:
                pv_info_phys = self.profile.phys_addr(pv_info_virt)
                pv_info = self.session.profile.pv_info(
                    offset=pv_info_phys,
                    vm=self.physical_address_space)

                if pv_info.paravirt_enabled and pv_info.paravirt_enabled == 1:
                    self.session.logging.debug(
                        "Detected paravirtualized XEN guest")
                    impl = "XenParaVirtAMD64PagedMemory"
                    as_class = addrspace.BaseAddressSpace.classes[impl]
                    return as_class

        elif self.profile.get_constant("arm_syscall"):
            # An ARM address space.
            self.session.logging.debug("Detected ARM Linux.")
            impl = "ArmPagedMemory"
            as_class = addrspace.BaseAddressSpace.classes[impl]
            return as_class

        return super(LinuxFindDTB, self).GetAddressSpaceImplementation()

    def dtb_hits(self):
        """Tries to locate the DTB."""
        if self.profile.metadata("arch") in ("I386", "MIPS", "ARM"):
            yield self.profile.phys_addr(
                self.profile.get_constant("swapper_pg_dir", is_address=True))

        else:
            yield self.profile.phys_addr(
                self.profile.get_constant("init_level4_pgt", is_address=True))

    def render(self, renderer):
        renderer.table_header([("DTB", "dtv", "[addrpad]"),
                               ("Valid", "valid", "")])

        for dtb in self.dtb_hits():
            renderer.table_row(dtb, self.VerifyHit(dtb) != None)


class LinuxPlugin(plugin.KernelASMixin, AbstractLinuxCommandPlugin):
    """Plugin which requires the kernel Address space to be loaded."""
    __abstract = True


class LinProcessFilter(LinuxPlugin):
    """A class for filtering processes."""

    __abstract = True

    @classmethod
    def args(cls, parser):
        super(LinProcessFilter, cls).args(parser)
        parser.add_argument("--pid", type="ArrayIntParser",
                            help="One or more pids of processes to select.")

        parser.add_argument("--proc_regex", default=None,
                            help="A regex to select a process by name.")

        parser.add_argument("--phys_task", type="ArrayIntParser",
                            help="Physical addresses of task structs.")

        parser.add_argument(
            "--task", type="ArrayIntParser",
            help="Kernel addresses of task structs.")

        parser.add_argument("--task_head", type="IntParser",
                            help="Use this as the first task to follow "
                            "the list.")

        parser.add_argument(
            "--method", choices=list(cls.METHODS), type="ChoiceArray",
            default=list(cls.METHODS),
            help="Method to list processes (Default uses all methods).")

    def __init__(self, pid=None, proc_regex=None, phys_task=None, task=None,
                 task_head=None, method=None, **kwargs):
        """Filters processes by parameters.

        Args:
           phys_task_struct: One or more task structs or offsets defined in
              the physical AS.

           pids: A list of pids.
           pid: A single pid.
        """
        super(LinProcessFilter, self).__init__(**kwargs)

        self.methods = method or sorted(self.METHODS)

        if isinstance(phys_task, (int, long)):
            phys_task = [phys_task]
        elif phys_task is None:
            phys_task = []

        if isinstance(task, (int, long)):
            task = [task]
        elif isinstance(task, obj.Struct):
            task = [task.obj_offset]
        elif task is None:
            task = []

        self.phys_task = phys_task
        self.task = task

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

        self.task_head = task_head

        # Sometimes its important to know if any filtering is specified at all.
        self.filtering_requested = (self.pids or self.proc_regex or
                                    self.phys_task or self.task)


    def list_from_task_head(self):
        task = self.profile.task_struct(
            offset=self.task_head, vm=self.kernel_address_space)

        return iter(task.tasks)

    def list_from_init_task(self, seen=None):
        task_head = self.profile.get_constant_object(
            "init_task", "task_struct", vm=self.kernel_address_space)

        for task in task_head.tasks:
            if task.obj_offset not in seen:
                seen.add(task.obj_offset)
                yield task

    def list_tasks(self):
        self.cache = self.session.GetParameter("pslist_cache")
        if not self.cache:
            self.cache = {}
            self.session.SetCache("pslist_cache", self.cache)

        seen = set()
        for proc in self.list_from_task_head():
            seen.add(proc.obj_offset)

        for k, handler in self.METHODS.items():
            if k in self.methods:
                if k not in self.cache:
                    self.cache[k] = set()
                    for proc in handler(self, seen=seen):
                        self.cache[k].add(proc.obj_offset)

                self.session.logging.debug("Listed %s processes using %s",
                                           len(self.cache[k]), k)
                seen.update(self.cache[k])

        # Sort by pid so that the output ordering remains stable.
        return sorted([self.profile.task_struct(x) for x in seen],
                      key=lambda x: x.pid)


    def filter_processes(self):
        """Filters task list using phys_task and pids lists."""
        # No filtering required:
        if not self.filtering_requested:
            for task in self.list_tasks():
                yield task
        else:
            # We need to filter by phys_task
            for offset in self.phys_task:
                yield self.virtual_process_from_physical_offset(offset)

            for offset in self.task:
                yield self.profile.task_struct(vm=self.kernel_address_space,
                                               offset=int(offset))

            # We need to filter by pids
            for task in self.list_tasks():
                if int(task.pid) in self.pids:
                    yield task
                elif self.proc_regex and self.proc_regex.match(
                        utils.SmartUnicode(task.comm)):
                    yield task


    def virtual_process_from_physical_offset(self, physical_offset):
        """Tries to return an task in virtual space from a physical offset.

        We do this by reflecting off the list elements.

        Args:
           physical_offset: The physical offset of the process.

        Returns:
           an _TASK object or a NoneObject on failure.
        """
        physical_task = self.profile.eprocess(offset=int(physical_offset),
                                              vm=self.kernel_address_space.base)

        # We cast our list entry in the kernel AS by following Flink into the
        # kernel AS and then the Blink. Note the address space switch upon
        # dereferencing the pointer.
        our_list_entry = physical_task.tasks.next.dereference(
            vm=self.kernel_address_space).prev.dereference()

        # Now we get the task_struct object from the list entry.
        return our_list_entry.dereference_as("task_struct", "tasks")

    METHODS = {
        "InitTask": list_from_init_task,
    }


class HeapScannerMixIn(object):
    """A mixin for converting a scanner into a heap only scanner."""

    def __init__(self, task=None, **kwargs):
        super(HeapScannerMixIn, self).__init__(**kwargs)
        self.task = task

    def scan(self, offset=0, maxlen=2**64): # pylint: disable=unused-argument
        for vma in self.task.mm.mmap.walk_list("vm_next"):
            start = max(vma.vm_start, self.task.mm.start_brk)
            end = min(vma.vm_end, self.task.mm.brk)

            # Only use the vmas inside the heap area.
            for hit in super(HeapScannerMixIn, self).scan(
                    offset=start, maxlen=end-start):
                yield hit


class KernelAddressCheckerMixIn(object):
    """A plugin mixin which does kernel address checks."""

    def __init__(self, **kwargs):
        super(KernelAddressCheckerMixIn, self).__init__(**kwargs)

        # We use the module plugin to help us local addresses inside kernel
        # modules.
        self.module_plugin = self.session.plugins.lsmod(session=self.session)


class Hostname(AbstractLinuxCommandPlugin):
    __name = "hostname"

    def get_hostname(self):
        hostname = ""

        pslist_plugin = self.session.plugins.pslist(session=self.session)
        for process in pslist_plugin.filter_processes():
            if not process.nsproxy or not process.nsproxy.uts_ns:
                continue
            task = process
            break

        profile = self.session.profile
        default_hostname = (profile.get_kernel_config("CONFIG_DEFAULT_HOSTNAME")
                            or "(none)")
        utsname = task.nsproxy.uts_ns.name
        nodename = utsname.nodename.cast("String")
        domainname = utsname.domainname.cast("String")
        if nodename != None:
            if domainname == default_hostname:
                hostname = nodename
            else:
                hostname = "%s.%s" % (nodename, domainname)
        return hostname

    def render(self, renderer):
        renderer.table_header([("Hostname", "hostname", "80")])
        renderer.table_row(self.get_hostname())
