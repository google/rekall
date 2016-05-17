# Rekall Memory Forensics
#
# Copyright 2015 Google Inc. All Rights Reserved.

# Authors:
# Michael Cohen <scudette@google.com>
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

"""Implement the base translating address spaces.

This is a complete rewrite of the previous translating address spaces
implemented in Rekall. The goals are:

1) To make a system that is provable and traceable - i.e. It should be possible
   to trace the address translation process step by step as it is performed by
   Rekall so we can verify how it is implemented.

2) The system must be very fast at the same time. Address translation can be an
   expensive operation so we need to ensure we are very quick.

3) The system must be extensible and modifiable. Address translation is a
   complex algorithm and varies a lot between operating systems and
   architectures. Therefore this implementation is generic and tries to
   encapsulate all the nuances of address translation in the OS specific
   implementation itself.

How does it work?
-----------------

There are a few main entry points into the translating Address Spaces:

1) vtop(): (Virtual to Physical) This method accepts a virtual address and
   translates it to the physical address in the base address space. This is the
   workhorse method. It is designed to be very fast but does not give too much
   information about how the translation was performed.

2) describe_vtop(): This is the describing sister method of vtop(). It returns a
   list of AddressTranslationDescriptor() objects. Each of these describes a
   specific step in the translation process. If one was to render each step,
   this outlines exactly what happened in each step and how the address is
   derived. If the address space translation process succeeds the last
   descriptor will be a PhysicalAddressDescriptor() instance which describes the
   final physical address. Note that the translation process may request files
   to be mapped into the physical address space, so the
   PhysicalAddressDescriptor() will point at mapped files (i.e. it may not
   actually refer to the physical memory image).

3) get_mappings(): This method generates Run instances which encapsulate each
   region available in the virtual address space.

The vtop() method and the describe_vtop() method are very similar since they
implement the same algorithms. However, we do not want to implement the same
thing twice because that leads to maintenance problems and subtle
bugs. Therefore vtop() is simply a wrapper around describe_vtop(). To achieve
the required performance vtop() simply looks for the PhysicalAddressDescriptor()
and returns it. This is essentially a noop for any of the other descriptors and
therefore maintains the same speed benefits.

"""
import StringIO
import struct

from rekall import addrspace
from rekall import config
from rekall import obj
from rekall import utils
from rekall.ui import text as text_renderer



config.DeclareOption(
    "dtb", group="Autodetection Overrides",
    type="IntParser", help="The DTB physical address.")

PAGE_SHIFT = 12
PAGE_MASK = ~ 0xFFF


class AddressTranslationDescriptor(object):
    """A descriptor of a step in the translation process.

    This is a class because there may be OS specific steps in the address
    translation.
    """
    object_name = None

    def __init__(self, object_name=None, object_value=None, object_address=None,
                 session=None):
        if object_name:
            self.object_name = object_name

        self.object_value = object_value
        self.object_address = object_address
        self.session = session

    def render(self, renderer):
        """Render this step."""
        if self.object_address is not None:
            # Properly format physical addresses.
            renderer.format(
                "{0}@ {1} = {2:addr}\n",
                self.object_name,
                self.session.physical_address_space.describe(
                    self.object_address),
                self.object_value or 0)
        elif self.object_value:
            renderer.format("{0} {1}\n",
                            self.object_name,
                            self.session.physical_address_space.describe(
                                self.object_value))
        else:
            renderer.format("{0}\n", self.object_name)


class CommentDescriptor(object):
    def __init__(self, comment, *args, **kwargs):
        self.session = kwargs.pop("session", None)
        self.comment = comment
        self.args = args

    def render(self, renderer):
        renderer.format(self.comment, *self.args)


class InvalidAddress(CommentDescriptor):
    """Mark an invalid address.

    This should be the last descriptor in the collection sequence.
    """


class DescriptorCollection(object):
    def __init__(self, session):
        self.session = session
        self.descriptors = []

    def add(self, descriptor_cls, *args, **kwargs):
        self.descriptors.append((descriptor_cls, args, kwargs))

    def __iter__(self):
        for cls, args, kwargs in self.descriptors:
            kwargs["session"] = self.session
            yield cls(*args, **kwargs)

    def __getitem__(self, item):
        """Get a particular descriptor.

        Descriptors can be requested by name (e.g. VirtualAddressDescriptor) or
        index (e.g. -1).
        """
        if isinstance(item, basestring):
            for descriptor_cls, args, kwargs in self.descriptors:
                if descriptor_cls.__name__ == item:
                    kwargs["session"] = self.session
                    return descriptor_cls(*args, **kwargs)

            return obj.NoneObject("No descriptor found.")
        try:
            cls, args, kwargs = self.descriptors[item]
            kwargs["session"] = self.session
            return cls(*args, **kwargs)
        except KeyError:
            return obj.NoneObject("No descriptor found.")

    def __unicode__(self):
        """Render ourselves into a string."""
        fd = StringIO.StringIO()
        ui_renderer = text_renderer.TextRenderer(
            session=self.session, fd=fd)

        with ui_renderer.start():
            for descriptor in self:
                descriptor.render(ui_renderer)

        return fd.getvalue()



class PhysicalAddressDescriptorCollector(DescriptorCollection):
    """A descriptor collector which only cares about PhysicalAddressDescriptor.

    This allows us to reuse all the code in describing the address space
    resolution and cheaply implement the standard vtop() method.
    """
    physical_address = None

    def add(self, descriptor_cls, *_, **kwargs):
        if descriptor_cls is PhysicalAddressDescriptor:
            address = kwargs.pop("address")
            self.physical_address = address


class PhysicalAddressDescriptor(AddressTranslationDescriptor):
    """A descriptor to mark the final physical address resolution."""

    def __init__(self, address=0, session=None):
        super(PhysicalAddressDescriptor, self).__init__(session=session)
        self.address = address

    def render(self, renderer):
        renderer.format(
            "Physical Address {0}\n",
            self.session.physical_address_space.describe(self.address))


class VirtualAddressDescriptor(AddressTranslationDescriptor):
    """Mark a virtual address."""

    def __init__(self, address=0, dtb=0, session=None):
        super(VirtualAddressDescriptor, self).__init__(session=session)
        self.dtb = dtb
        self.address = address

    def render(self, renderer):
        renderer.format(
            "Virtual Address {0:style=address} (DTB {1:style=address})\n",
            self.address, self.dtb)


class IA32PagedMemory(addrspace.PagedReader):
    """Standard x86 32 bit non PAE address space.

    Provides an address space for IA32 paged memory, aka the x86
    architecture, without Physical Address Extensions (PAE). Allows
    callers to map virtual address to offsets in physical memory.

    Create a new IA32 address space without PAE to sit on top of
    the base address space and a Directory Table Base (CR3 value)
    of 'dtb'.

    Comments in this class mostly come from the Intel(R) 64 and IA-32
    Architectures Software Developer's Manual Volume 3A: System Programming
    Guide, Part 1, revision 031, pages 4-8 to 4-15. This book is available
    for free at http://www.intel.com/products/processor/manuals/index.htm.
    Similar information is also available from Advanced Micro Devices (AMD)
    at http://support.amd.com/us/Processor_TechDocs/24593.pdf.

    This address space implements paging as described in section "4.3 32-BIT
    PAGING" of the above book.

    This is simplified from previous versions of rekall, by removing caching
    and automated DTB searching (which is now performed by specific plugins in
    an OS specific way).

    """
    order = 70

    valid_mask = 1

    def __init__(self, name=None, dtb=None, **kwargs):
        """Instantiate an Intel 32 bit Address space over the layered AS.

        Args:
          dtb: The dtb address.
        """
        super(IA32PagedMemory, self).__init__(**kwargs)

        # We must be stacked on someone else:
        if self.base == None:
            raise TypeError("No base Address Space")

        # If the underlying address space already knows about the dtb we use it.
        # Allow the dtb to be specified in the session.
        self.dtb = dtb or self.session.GetParameter("dtb")

        if not self.dtb != None:
            raise TypeError("No valid DTB specified. Try the find_dtb"
                            " plugin to search for the dtb.")
        self.name = (name or 'Kernel AS') + "@%#x" % self.dtb

        # Use a TLB to make this faster.
        self._tlb = addrspace.TranslationLookasideBuffer(1000)

        self._cache = utils.FastStore(100)

        # Some important masks we can use.

        # Is the pagesize flags on?
        self.page_size_mask = (1 << 7)

    def vtop(self, vaddr):
        """Translates virtual addresses into physical offsets.

        The function should return either None (no valid mapping)
        or the offset in physical memory where the address maps.

        This function is simply a wrapper around describe_vtop() which does all
        the hard work. You probably never need to override it.
        """
        vaddr = int(vaddr)

        try:
            return self._tlb.Get(vaddr)
        except KeyError:
            # The TLB accepts only page aligned virtual addresses.
            aligned_vaddr = vaddr & self.PAGE_MASK
            collection = self.describe_vtop(
                aligned_vaddr, PhysicalAddressDescriptorCollector(self.session))

            self._tlb.Put(aligned_vaddr, collection.physical_address)
            return self._tlb.Get(vaddr)

    def vtop_run(self, addr):
        phys_addr = self.vtop(addr)
        if phys_addr is not None:
            return addrspace.Run(
                start=addr,
                end=addr,
                file_offset=phys_addr,
                address_space=self.base)

    def describe_vtop(self, vaddr, collection=None):
        """A generator of descriptive statements about stages in translation.

        While the regular vtop is called very frequently and therefore must be
        fast, this variation is used to examine the translation process in
        detail. We therefore emit data about each step of the way - potentially
        re-implementing the vtop() method above, but yielding intermediate
        results.

        Args:
          vaddr: The address to translate.
          collection: An instance of DescriptorCollection() which will receive
            the address descriptors. If not provided we create a new collection.

        Returns
          A list of AddressTranslationDescriptor() instances.

        """
        if collection is None:
            collection = DescriptorCollection(self.session)

        # Bits 31:12 are from CR3.
        # Bits 11:2 are bits 31:22 of the linear address.
        pde_addr = ((self.dtb & 0xfffff000) |
                    ((vaddr & 0xffc00000) >> 20))
        pde_value = self.read_pte(pde_addr, collection=collection)
        collection.add(AddressTranslationDescriptor,
                       object_name="pde", object_value=pde_value,
                       object_address=pde_addr)

        if not pde_value & self.valid_mask:
            collection.add(InvalidAddress, "Invalid PDE")
            return collection

        # Large page PDE.
        if pde_value & self.page_size_mask:
            # Bits 31:22 are bits 31:22 of the PDE
            # Bits 21:0 are from the original linear address
            physical_address = (pde_value & 0xffc00000) | (vaddr & 0x3fffff)
            collection.add(CommentDescriptor, "Large page mapped\n")
            collection.add(PhysicalAddressDescriptor, address=physical_address)

            return collection

        # Bits 31:12 are from the PDE
        # Bits 11:2 are bits 21:12 of the linear address
        pte_addr = (pde_value & 0xfffff000) | ((vaddr & 0x3ff000) >> 10)
        pte_value = self.read_pte(pte_addr, collection=collection)
        self.describe_pte(collection, pte_addr, pte_value, vaddr)

        return collection

    def describe_pte(self, collection, pte_addr, pte_value, vaddr):
        collection.add(AddressTranslationDescriptor,
                       object_name="pte", object_value=pte_value,
                       object_address=pte_addr)

        if pte_value & self.valid_mask:
            # Bits 31:12 are from the PTE
            # Bits 11:0 are from the original linear address
            phys_addr = ((pte_value & 0xfffff000) |
                         (vaddr & 0xfff))

            collection.add(PhysicalAddressDescriptor, address=phys_addr)
        else:
            collection.add(InvalidAddress, "Invalid PTE")

        return collection

    def read_pte(self, addr, collection=None):
        """Read an unsigned 32-bit integer from physical memory.

        Note this always succeeds - reads outside mapped addresses in the image
        will simply return 0.
        """
        _ = collection
        string = self.base.read(addr, 4)
        return struct.unpack('<I', string)[0]

    def get_mappings(self, start=0, end=2**64):
        """Enumerate all valid memory ranges.

        Yields:
          tuples of (starting virtual address, size) for valid the memory
          ranges.
        """
        # Pages that hold PDEs and PTEs are 0x1000 bytes each.
        # Each PDE and PTE is four bytes. Thus there are 0x1000 / 4 = 0x400
        # PDEs and PTEs we must test
        for pde in range(0, 0x400):
            vaddr = pde << 22
            if vaddr > end:
                return

            next_vaddr = (pde + 1) << 22
            if start > next_vaddr:
                continue

            pde_addr = ((self.dtb & 0xfffff000) |
                        (vaddr & 0xffc00000) >> 20)
            pde_value = self.read_pte(pde_addr)
            if not pde_value & self.valid_mask:
                continue

            # PDE is for a large page.
            if pde_value & self.page_size_mask:
                yield addrspace.Run(
                    start=vaddr,
                    end=vaddr + 0x400000,
                    file_offset=(pde_value & 0xffc00000) | (vaddr & 0x3fffff),
                    address_space=self.base)
                continue

            # This reads the entire PTE table at once - On
            # windows where IO is extremely expensive, its
            # about 10 times more efficient than reading it
            # one value at the time - and this loop is HOT!
            pte_table_addr = ((pde_value & 0xfffff000) |
                              ((vaddr & 0x3ff000) >> 10))

            data = self.base.read(pte_table_addr, 4 * 0x400)
            pte_table = struct.unpack("<" + "I" * 0x400, data)

            tmp1 = vaddr
            for i, pte_value in enumerate(pte_table):
                vaddr = tmp1 | i << 12
                if vaddr > end:
                    return

                next_vaddr = tmp1 | ((i + 1) << 12)

                if start > next_vaddr:
                    continue

                if pte_value & self.valid_mask:
                    yield addrspace.Run(
                        start=vaddr,
                        end=vaddr + 0x1000,
                        file_offset=(pte_value & 0xfffff000) | (vaddr & 0xfff),
                        address_space=self.base)

    def __str__(self):
        return "%s@0x%08X (%s)" % (self.__class__.__name__, self.dtb, self.name)

    def __eq__(self, other):
        return (super(IA32PagedMemory, self).__eq__(other) and
                self.dtb == other.dtb and self.base == other.base)

    def end(self):
        return (2 ** 32) - 1


class IA32PagedMemoryPae(IA32PagedMemory):
    """Standard x86 32 bit PAE address space.

    Provides an address space for IA32 paged memory, aka the x86
    architecture, with Physical Address Extensions (PAE) enabled. Allows
    callers to map virtual address to offsets in physical memory.

    Comments in this class mostly come from the Intel(R) 64 and IA-32
    Architectures Software Developer's Manual Volume 3A: System Programming
    Guide, Part 1, revision 031, pages 4-15 to 4-23. This book is available
    for free at http://www.intel.com/products/processor/manuals/index.htm.
    Similar information is also available from Advanced Micro Devices (AMD)
    at http://support.amd.com/us/Processor_TechDocs/24593.pdf.

    This implements the translation described in Section "4.4.2 Linear-Address
    Translation with PAE Paging".

    """
    order = 80

    __pae = True

    def describe_vtop(self, vaddr, collection=None):
        """Explain how a specific address was translated.

        Returns:
          a list of AddressTranslationDescriptor() instances.
        """
        if collection is None:
            collection = DescriptorCollection(self.session)

        # Bits 31:5 come from CR3
        # Bits 4:3 come from bits 31:30 of the original linear address
        pdpte_addr = ((self.dtb & 0xffffffe0) |
                      ((vaddr & 0xC0000000) >> 27))
        pdpte_value = self.read_pte(pdpte_addr)

        collection.add(AddressTranslationDescriptor,
                       object_name="pdpte", object_value=pdpte_value,
                       object_address=pdpte_addr)

        if not pdpte_value & self.valid_mask:
            collection.add(InvalidAddress, "Invalid PDPTE")
            return collection

        # Bits 51:12 are from the PDPTE
        # Bits 11:3 are bits 29:21 of the linear address
        pde_addr = (pdpte_value & 0xfffff000) | ((vaddr & 0x3fe00000) >> 18)
        self._describe_pde(collection, pde_addr, vaddr)

        return collection

    def _describe_pde(self, collection, pde_addr, vaddr):
        pde_value = self.read_pte(pde_addr)
        collection.add(AddressTranslationDescriptor,
                       object_name="pde", object_value=pde_value,
                       object_address=pde_addr)

        if not pde_value & self.valid_mask:
            collection.add(InvalidAddress, "Invalid PDE")

        # Large page PDE accesses 2mb region.
        elif pde_value & self.page_size_mask:
            # Bits 51:21 are from the PDE
            # Bits 20:0 are from the original linear address
            physical_address = ((pde_value & 0xfffffffe00000) |
                                (vaddr & 0x1fffff))
            collection.add(CommentDescriptor, "Large page mapped\n")
            collection.add(PhysicalAddressDescriptor, address=physical_address)

        else:
            # Bits 51:12 are from the PDE
            # Bits 11:3 are bits 20:12 of the original linear address
            pte_addr = (pde_value & 0xffffffffff000) | ((vaddr & 0x1ff000) >> 9)
            pte_value = self.read_pte(pte_addr)

            self.describe_pte(collection, pte_addr, pte_value, vaddr)

    def describe_pte(self, collection, pte_addr, pte_value, vaddr):
        collection.add(AddressTranslationDescriptor,
                       object_name="pte", object_value=pte_value,
                       object_address=pte_addr)

        if pte_value & self.valid_mask:
            # Bits 51:12 are from the PTE
            # Bits 11:0 are from the original linear address
            physical_address = (pte_value & 0xffffffffff000) | (vaddr & 0xfff)
            collection.add(PhysicalAddressDescriptor, address=physical_address)
        else:
            collection.add(InvalidAddress, "Invalid PTE\n")

        return collection

    def read_pte(self, addr, collection=None):
        '''
        Returns an unsigned 64-bit integer from the address addr in
        physical memory. If unable to read from that location, returns None.
        '''
        try:
            return self._cache.Get(addr)
        except KeyError:
            string = self.base.read(addr, 8)
            result = struct.unpack('<Q', string)[0]
            self._cache.Put(addr, result)

            return result

    def get_mappings(self, start=0, end=2**64):
        """A generator of address, length tuple for all valid memory regions."""
        # Pages that hold PDEs and PTEs are 0x1000 bytes each.
        # Each PDE and PTE is eight bytes. Thus there are 0x1000 / 8 = 0x200
        # PDEs and PTEs we must test.
        for pdpte_index in range(0, 4):
            vaddr = pdpte_index << 30
            if vaddr > end:
                return

            next_vaddr = (pdpte_index + 1) << 30
            if start >= next_vaddr:
                continue

            # Bits 31:5 come from CR3
            # Bits 4:3 come from bits 31:30 of the original linear address
            pdpte_addr = (self.dtb & 0xffffffe0) | ((vaddr & 0xc0000000) >> 27)
            pdpte_value = self.read_pte(pdpte_addr)
            if not pdpte_value & self.valid_mask:
                continue

            tmp1 = vaddr
            for pde_index in range(0, 0x200):
                vaddr = tmp1 | (pde_index << 21)
                if vaddr > end:
                    return

                next_vaddr = tmp1 | ((pde_index + 1) << 21)
                if start >= next_vaddr:
                    continue

                # Bits 51:12 are from the PDPTE
                # Bits 11:3 are bits 29:21 of the linear address
                pde_addr = ((pdpte_value & 0xffffffffff000) |
                            ((vaddr & 0x3fe00000) >> 18))
                pde_value = self.read_pte(pde_addr)
                if not pde_value & self.valid_mask:
                    continue

                if pde_value & self.page_size_mask:
                    yield addrspace.Run(
                        start=vaddr,
                        end=vaddr+0x200000,
                        file_offset=(pde_value & 0xfffffffe00000) | (
                            vaddr & 0x1fffff),
                        address_space=self.base)
                    continue

                # This reads the entire PTE table at once - On
                # windows where IO is extremely expensive, its
                # about 10 times more efficient than reading it
                # one value at the time - and this loop is HOT!
                pte_table_addr = ((pde_value & 0xffffffffff000) |
                                  ((vaddr & 0x1ff000) >> 9))

                data = self.base.read(pte_table_addr, 8 * 0x200)
                pte_table = struct.unpack("<" + "Q" * 0x200, data)

                tmp2 = vaddr
                for i, pte_value in enumerate(pte_table):
                    if pte_value & self.valid_mask:
                        vaddr = tmp2 | i << 12
                        if vaddr > end:
                            return

                        next_vaddr = tmp2 | (i + 1) << 12
                        if start >= next_vaddr:
                            continue

                        yield addrspace.Run(
                            start=vaddr,
                            end=vaddr+0x1000,
                            file_offset=((pte_value & 0xffffffffff000) |
                                         (vaddr & 0xfff)),
                            address_space=self.base)
