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
from rekall import addrspace
from rekall import config
from rekall import obj
import struct

config.DeclareOption(name="dtb", group="Autodetection Overrides",
                     action=config.IntParser,
                     help="The DTB physical address.")

pointer_size = 4
page_shift = 12
ptrs_per_pte = 1024
ptrs_per_pgd = 1024
user_ptrs_per_pgd = 512
pgdir_shift = 22
ptrs_page = 2048
pfn_shift = 11


class MipsAddressSpace(addrspace.PagedReader):
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
    '''
    order = 70

    def __init__(self, name=None, dtb=None, **kwargs):

        super(MipsAddressSpace, self).__init__(**kwargs)

        ## We must be stacked on someone else:
        if not self.base != self:
            raise TypeError("No base Address Space")

        # If the underlying address space already knows about the dtb we use it.
        # Allow the dtb to be specified in the session.
        self.dtb = dtb or self.session.GetParameter("dtb")

        if not self.dtb != None:
            raise TypeError("No valid DTB specified. Try the find_dtb"
                            " plugin to search for the dtb.")
        self.name = (name or 'Kernel AS') + "@%#x" % self.dtb

    def __pa(self, x):
        if x >= 0xA0000000:
            return x - 0xA0000000
        else:
            return x - 0x80000000


    def read_long_phys(self, addr):
        '''
        Returns an unsigned 32-bit integer from the address addr in
        physical memory. If unable to read from that location, returns None.
        '''
        string = self.base.read(addr & 0x7fffffff, 4)
        return struct.unpack('>I', string)[0]

    def pgd_index(self, vaddr):
        return (vaddr >> pgdir_shift) & (ptrs_per_pgd - 1)

    def get_pgd(self, vaddr):
        pgd_entry = self.dtb + self.pgd_index(vaddr) * pointer_size
        return self.read_long_phys(pgd_entry)

    def pte_pfn(self, pte):
        return pte >> pfn_shift

    def pte_index(self, pte):
        return (pte >> page_shift) & (ptrs_per_pte - 1)

    def get_pte(self, vaddr, pgd):
        pgd_val = pgd & ~((1 << page_shift) - 1)
        pgd_val = pgd_val + self.pte_index(vaddr) * pointer_size
        return self.read_long_phys(pgd_val)

    def get_paddr(self, vaddr, pte):
        return (self.pte_pfn(pte) << page_shift) | (vaddr & ((1 << page_shift) - 1))

    def entry_present(self, entry):
        if entry:
            if (entry & 1):
                return True

        return False

    def vtop(self, vaddr):
        if vaddr == None:
            return None

        if (vaddr >= 0x80000000) and (vaddr < 0xC0000000):
            if self.base.is_valid_address(self.__pa(vaddr)):
                return self.__pa(vaddr)
            else:
                return None
        else:
            pgd = self.get_pgd(vaddr)

        pte = self.get_pte(vaddr, pgd)
        if not pte:
            return None

        if not self.entry_present(pte):
            return None

        return self.get_paddr(vaddr, pte)

    def get_available_addresses(self, start=0):
        # Need to find out if we're mapping for kernel space
        # or userspace
        sym = self.__pa(self.session.profile.get_constant('swapper_pg_dir'))
        if self.dtb == sym:
            num_pgd = ptrs_per_pgd
        else:
            num_pgd = user_ptrs_per_pgd
        for pgd_index in range(0, num_pgd):
            vaddr = pgd_index << pgdir_shift
            pgd = self.get_pgd(vaddr)
            for pte_index in range(0, ptrs_per_pte):
                va = vaddr + (pte_index << page_shift)
                if start >= va:
                    continue
                if (va >= 0x80000000) and (va < 0xC0000000):
                    if self.base.is_valid_address(self.__pa(va)):
                        yield (va, self.__pa(va), self.PAGE_SIZE)
                    continue

                pte = self.get_pte(va, pgd)
                if self.entry_present(pte):
                    phys = self.get_paddr(va, pte)
                    yield (va, phys, self.PAGE_SIZE)
