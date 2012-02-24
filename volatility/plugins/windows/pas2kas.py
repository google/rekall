import time
import bisect
import logging

from volatility.plugins.windows import common

import volatility.conf as conf
import volatility.utils as utils
from volatility import plugin
import volatility.commands as commands
import volatility.win32 as win32
import bisect
from volatility.cache import CacheDecorator


def parse_int(string):
   if string.startswith("0x"):
      return int(string, 16)
   return int(string)   

class pas2kas(commands.command):
    """ Convert a list of physical AS offsets (given on the command
    line) to a list of potential KVA addresses.
    """
    def __init__(self, *args):
        commands.command.__init__(self, *args)
        self._config.add_option('PID', short_option = 'p', default=None,
				cache_invalidator=False,
				help='Operate on this Process ID',
				action='store', type='int')

    def render_text(self, outfd, data):
        outfd.write("{0:10s} {1:10s}\n".format("Phys AS", "KAS"))
        for offset, result in data:
            outfd.write("0x{0:08x} 0x{1:08x}\n".format(offset, result))

    def coalesce_ranges(self, addr_space):
        """ Coalesce the page range given into large groups """
        last_va = 0
        last_pa = 0
        last_len = 0
        for va, length in addr_space.get_available_pages():
            pa = addr_space.vtop(va)
            if pa == None:
                continue

            ## This page is right after the last page in the range
            if (va - last_va) == (pa - last_pa):
                last_len += length
            else:
                if last_len>0:
                    yield (last_va, last_pa, last_len)

                last_va, last_pa, last_len = va, pa, length

        yield (last_va, last_pa, last_len)

    def get_task_as(self, kernel_addr_space):
        if self._config.PID:
            for t in win32.tasks.pslist(kernel_addr_space):
                if t.UniqueProcessId == self._config.PID:
                    return t.get_process_address_space()

            raise RuntimeError("Unable to locate pid %s" % self._config.PID)

        return kernel_addr_space

    ## This caches the mapping per each pid so we dont need to
    ## invalidate on different pids
    @CacheDecorator(lambda self: "address_space/memory_translation/"
                    "pas2kas/pid-{0}".format(self._config.PID))

    def get_ranges(self):
        addr_space = self.get_task_as(utils.load_as(self._config))

        ## Get the coalesced map:
        ranges = [ (va, pa, length) for va, pa, length in self.coalesce_ranges(addr_space) ]

        return ranges

    def calculate(self):
        ranges = self.get_ranges()

        ## Now for each Physical address, find all Virtual Addresses
        ## for it. We optimise by sorting on pa and use binary
        ## search via the bisect module to get O(log n) here.
        self._config.parse_options()
        for pa in self._config.args[1:]:
            needle = parse_int(pa)
            for va, pa, length in ranges:
                if needle >= pa and needle - pa < length:
                    yield (needle, va + (needle - pa))


class Pas2Vas(common.WinProcessFilter):
    """Resolves a physical address to a virtual addrress in a process."""

    __name = "pas2vas"

    def __init__(self, include_processes=False, **kwargs):
        """Resolves a physical address to a vertial address.

        Often a user might want to see which process maps a particular physical
        offset. In reality the same physical memory can be mapped into multiple
        processes (and the kernel) at the same time. Usually since the kernel
        memory is mapped into each process's address space, a single physical
        offset which is mapped into the kernel will also be mapped into each
        process.

        The only way to tell if a physical page is mapped into a process is to
        enumerate all process maps and then search them for the physical
        offset. This takes a fair bit of memory and effort to build so by
        default we store the maps in the session for quick reuse.

        Args:
          include_processes: If this is specified we also include process
          address spaces, otherwise only the kernel.
        """
        super(Pas2Vas, self).__init__(**kwargs)

        # Now we build the tables for each process. We do this simply by listing
        # all the tasks using pslist, and then for each task we get its address
        # space, and enumerate available pages.

        self.maps = {}

        if include_processes:
           for task in self.filter_processes():
              task_as = task.get_process_address_space()
              pid = int(task.UniqueProcessId)

              # All kernel processes have the same page tables.
              if task_as.dtb == self.kernel_address_space.dtb:
                 pid = "kernel"

              self.build_address_map(task_as, pid)
        else:
           self.build_address_map(self.kernel_address_space, "kernel")

    def build_address_map(self, virtual_address_space, pid):
       """Given the virtual_address_space, build the address map."""
       logging.debug("Loading maps for pid %s" % pid)

       if pid not in self.maps:
          mapper = self.session.plugins.memmap(session=self.session)

          # This lookup map is sorted by the physical address. We then use
          # bisect to efficiently look up the physical page.
          t = time.time()
          tmp_lookup_map = []
          for va, length in virtual_address_space.get_available_pages():
             pa = virtual_address_space.vtop(va)
             tmp_lookup_map.append((pa, length, va))

          tmp_lookup_map.sort()
          self.maps[pid] = tmp_lookup_map

          logging.debug("Lookup map was %s large in %s sec.",
                        len(tmp_lookup_map), time.time() - t)

    def get_virtual_address(self, physical_address):
       for pid, lookup_map in self.maps.items():
          if physical_address < lookup_map[0][0]:
             continue

          # This efficiently find the entry in the map just below the
          # physical_address.
          lookup_pa, length, lookup_va = lookup_map[
             bisect.bisect(lookup_map, (physical_address, 0, 0))-1]

          if lookup_pa < physical_address and lookup_pa + length > physical_address:
             # Yield the pid and the virtual offset
             yield pid, lookup_va + physical_address - lookup_pa
