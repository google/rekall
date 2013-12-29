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

from rekall import args
from rekall import obj
from rekall import plugin
from rekall import utils

from rekall.plugins import core


class AbstractLinuxCommandPlugin(plugin.PhysicalASMixin,
                                 plugin.ProfileCommand):
    """A base class for all linux based plugins."""
    __abstract = True

    @classmethod
    def is_active(cls, config):
        """We are only active if the profile is linux."""
        return (getattr(config.profile, "_md_os", None) == 'linux' and
                plugin.Command.is_active(config))


class LinuxFindDTB(AbstractLinuxCommandPlugin):
    """A scanner for DTB values.

    For linux, the dtb values are taken directly from the symbol file. Linux has
    a direct mapping between the kernel virtual address space and the physical
    memory.  This is the difference between the virtual and physical addresses
    (aka PAGE_OFFSET). This is defined by the __va macro:

    #define __va(x) ((void *)((unsigned long) (x) + PAGE_OFFSET))

    This one plugin handles both 32 and 64 bits.
    """

    __name = "find_dtb"

    def dtb_hits(self):
        """Tries to locate the DTB."""
        if self.profile.metadata("memory_model") == "32bit":
            PAGE_OFFSET = (self.profile.get_constant("_text") -
                           self.profile.get_constant("phys_startup_32"))

            yield self.profile.get_constant("swapper_pg_dir") - PAGE_OFFSET, None
        else:
            PAGE_OFFSET = (self.profile.get_constant("_text") -
                           self.profile.get_constant("phys_startup_64"))

            yield self.profile.get_constant("init_level4_pgt") - PAGE_OFFSET, None

    def verify_address_space(self, address_space=None, **kwargs):
        # There is not really much we can do if the address space is wrong, so
        # we just keep going.
        return True

    def render(self, renderer):
        renderer.table_header([("DTB", "dtv", "[addrpad]"),
                               ("Valid", "valid", "")])

        for dtb, _ in self.dtb_hits():
            address_space = core.GetAddressSpaceImplementation(self.profile)(
                session=self.session, base=self.physical_address_space, dtb=dtb)

            renderer.table_row(
                dtb, self.verify_address_space(address_space=address_space))

class LinuxPlugin(plugin.KernelASMixin, AbstractLinuxCommandPlugin):
    """Plugin which requires the kernel Address space to be loaded."""
    __abstract = True


class LinProcessFilter(LinuxPlugin):
    """A class for filtering processes."""

    __abstract = True

    @classmethod
    def args(cls, parser):
        super(LinProcessFilter, cls).args(parser)
        parser.add_argument("--pid",
                            action=args.ArrayIntParser, nargs="+",
                            help="One or more pids of processes to select.")

        parser.add_argument("--proc_regex", default=None,
                            help="A regex to select a process by name.")

        parser.add_argument("--phys_task",
                            action=args.ArrayIntParser, nargs="+",
                            help="Physical addresses of task structs.")

        parser.add_argument("--task", action=args.ArrayIntParser, nargs="+",
                            help="Kernel addresses of task structs.")

        parser.add_argument("--task_head", action=args.IntParser,
                            help="Use this as the process head. If "
                            "specified we do not use kdbg.")


    def __init__(self, pid=None, proc_regex=None, phys_task=None, task=None,
                 task_head=None, **kwargs):
        """Filters processes by parameters.

        Args:
           phys_task_struct: One or more task structs or offsets defined in
              the physical AS.

           pids: A list of pids.
           pid: A single pid.
        """
        super(LinProcessFilter, self).__init__(**kwargs)

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

        # Without a specified task head, we use the init_task from the symbol
        # table.
        if task_head is None:
            task_head = self.profile.get_constant("init_task")

        self.task_head = task_head

        # Sometimes its important to know if any filtering is specified at all.
        self.filtering_requested = (self.pids or self.proc_regex or
                                    self.phys_task or self.task)

    def list_tasks(self):
        task = self.profile.task_struct(
            offset=self.task_head, vm=self.kernel_address_space)

        return iter(task.tasks)

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
           physical_offset: The physcial offset of the process.

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


class HeapScannerMixIn(object):
    """A mixin for converting a scanner into a heap only scanner."""
    def scan(self, **kwargs):
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



# TODO: Deprecate this when all plugins have been converted.
class AbstractLinuxCommand(object):

    def __init__(self, *args, **kwargs):
        self.addr_space = utils.load_as(self._config)
        self.profile = self.addr_space.profile
        self.smap = self.profile.sys_map

    @classmethod
    def is_active(cls, session):
        """We are only active if the profile is Linux."""
        try:
            return session.profile and session.profile._md_os == 'linux'
        except profile.Error:
            return True


def offsetof(struct_name, list_member, profile):

    offset = profile.typeDict[struct_name][1][list_member][0]
    return offset

def bit_is_set(bmap, pos):

    mask = 1 << pos
    return bmap & mask

# returns a list of online cpus (the processor numbers)
def online_cpus(smap, addr_space):

    #later kernels..
    if "cpu_online_bits" in smap:
        bmap = obj.Object("unsigned long", offset=smap["cpu_online_bits"], vm=addr_space)

    elif "cpu_present_map" in smap:
        bmap = obj.Object("unsigned long",  offset=smap["cpu_present_map"], vm=addr_space)

    else:
        raise AttributeError, "Unable to determine number of online CPUs for memory capture"

    cpus = []
    for i in xrange(0, 8):
        if bit_is_set(bmap, i):
            cpus.append(i)

    return cpus

def walk_per_cpu_var(obj_ref, per_var, var_type):

    cpus = online_cpus(obj_ref.smap, obj_ref.addr_space)

    # get the highest numbered cpu
    max_cpu = cpus[-1]

    per_offsets = obj.Object(theType='Array', targetType='unsigned long', count=max_cpu, offset=obj_ref.smap["__per_cpu_offset"], vm=obj_ref.addr_space)
    i = 0

    for i in cpus:

        offset = per_offsets[i]

        addr = obj_ref.smap["per_cpu__" + per_var] + offset.v()
        var = obj.Object(var_type, offset=addr, vm=obj_ref.addr_space)

        yield i, var


def S_ISDIR(mode):
    return (mode & linux_flags.S_IFMT) == linux_flags.S_IFDIR

def S_ISREG(mode):
    return (mode & linux_flags.S_IFMT) == linux_flags.S_IFREG





