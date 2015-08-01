# Rekall Memory Forensics
#
# Authors:
# Karl Vogel <karl.vogel@gmail.com>
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

import struct

from rekall import addrspace
from rekall import config
from rekall.plugins.addrspaces import intel

class MIPS32PagedMemory(intel.IA32PagedMemory):
    '''
    Address space to handle the MIPS Linux memory layout, which is:

    0x0000 0000 - 0x7FFF FFFF  kuseg: User mapped pages
    0x8000 0000 - 0x9FFF FFFF  k0seg: Kernel non paged memory, this maps to
                                      address range 0x0000 0000 - 0x1FFF FFFF
    0xA000 0000 - 0xBFFF FFFF  k1seg: Kernel non paged, non cached memory,
                                      this maps to address range
                                      0x0000 0000 - 0x1FFF FFFF
    0xC000 0000 - 0xFFFF FFFF  k2seg: Kernel paged memory using init_mm.pgd

    See page 8 on:
      http://www.eecs.harvard.edu/~margo/cs161/notes/vm-mips.pdf

    Derives from IA32PagedMemory as the only major difference is the special
    layout as shown above and minor details like no large pages and a difference
    in the PTE to PFN translation, which is taken care of by the
    pte_paddr function.
    '''

    # MIPS32 doesn't have a valid flag on PDE's, they're always valid
    valid_mask = (1 << 32) - 1

    def _pa(self, x):
        '''
        Convert a physical address to the actual physical memory location.
        '''
        if x < 0x80000000:
            return x
        elif x >= 0xA0000000:
            return x - 0xA0000000
        else:
            return x - 0x80000000

    def page_size_flag(self, entry):
        '''
        MIPS32 doesn't have a page size flag, always return False
        '''
        return False

    def read_long_phys(self, addr):
        '''
        Returns an unsigned 32-bit integer from the address addr in
        physical memory. If unable to read from that location, returns None.
        '''
        string = self.base.read(self._pa(addr), 4)
        return struct.unpack('>I', string)[0]

    def vtop(self, vaddr):
        '''
        Translates virtual addresses into physical offsets.
        The function should return either None (no valid mapping)
        or the offset in physical memory where the address maps.
        '''
        if (vaddr >= 0x80000000) and (vaddr < 0xC0000000):
            return self._pa(vaddr)

        return super(MIPS32PagedMemory, self).vtop(vaddr)

    def pte_paddr(self, pte):
        '''
        Return the physical address for the given PTE.
        This should return:
           (pte >> pfn_shift) << page_shift

        On MIPS pfn_shift is 11, while page_shift is 12
        '''
        return pte << 1

    def get_phys_addr(self, vaddr, pte_value):
        '''
        Return the offset in a 4KB memory page from the given virtual
        address and Page Table Entry.

        Bits 31:12 are from the PTE
        Bits 11:0 are from the original linear address
        '''
        if pte_value & self.valid_mask:
            return (self.pte_paddr(pte_value) & 0xfffff000) | (vaddr & 0xfff)

    def get_available_addresses(self, start=0):
        """Enumerate all valid memory ranges.

        Yields:
          tuples of (starting virtual address, size) for valid the memory
          ranges.
        """
        # Need to find out if we're mapping for kernel space
        # or userspace
        sym = self._pa(self.session.profile.get_constant('swapper_pg_dir'))
        if self.dtb == sym:
            num_pde = 1024
        else:
            num_pde = 512

        # Pages that hold PDEs and PTEs are 0x1000 bytes each.
        # Each PDE and PTE is four bytes. Thus there are 0x1000 / 4 = 0x400
        # PDEs and PTEs we must test
        # On MIPS, the userspace PDEs are limited to 512 entries
        for pde in range(0, num_pde):
            vaddr = pde << 22
            next_vaddr = (pde+1) << 22
            if start > next_vaddr:
                continue

            if (vaddr >= 0x80000000) and (vaddr < 0xC0000000):
                yield (vaddr, self._pa(vaddr), 1 << 22)
                continue

            pde_value = self.get_pde(vaddr)

            # This reads the entire PTE table at once - On
            # windows where IO is extremely expensive, its
            # about 10 times more efficient than reading it
            # one value at the time - and this loop is HOT!
            pte_table_addr = ((pde_value & 0xfffff000) |
                              ((vaddr & 0x3ff000) >> 10))

            data = self.base.read(self._pa(pte_table_addr), 4 * 0x400)
            pte_table = struct.unpack(">" + "I" * 0x400, data)

            tmp1 = vaddr
            for i, pte_value in enumerate(pte_table):
                vaddr = tmp1 | i << 12
                next_vaddr = tmp1 | ((i+1) << 12)

                if start > next_vaddr:
                    continue

                if pte_value & self.valid_mask:
                    yield (vaddr,
                           self.get_phys_addr(vaddr, pte_value),
                           0x1000)
