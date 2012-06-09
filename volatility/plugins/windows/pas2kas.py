import logging
import bisect

from volatility.plugins.windows import common
from volatility import plugin
from volatility.cache import CacheDecorator


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
          for va, length in virtual_address_space.get_available_addresses():
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
