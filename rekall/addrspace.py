# Rekall Memory Forensics
# Copyright (C) 2007,2008 Volatile Systems
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Original Source:
# Copyright (C) 2004,2005,2006 4tphi Research
# Author: {npetroni,awalters}@4tphi.net (Nick Petroni and AAron Walters)
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

"""
@author:       AAron Walters
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com
@organization: Volatile Systems

   Alias for all address spaces

"""
from rekall import registry
from rekall import utils


class BaseAddressSpace(object):
    """ This is the base class of all Address Spaces. """

    __metaclass__ = registry.MetaclassRegistry
    __abstract = True

    order = 10

    # This can be used to name the address space (e.g. process if etc).
    name = ""

    # Some useful metadata for address spaces.

    # This signifies that this address space normally operates on memory
    # images. This flag controls if this address space will participate in
    # address space autoselection for image detection. Note that it can not be
    # inherited but must be explicitly set.
    __image = False

    def __init__(self, base=None, session=None, write=False, profile=None,
                 **_):
        """Base is the AS we will be stacking on top of, opts are options which
        we may use.

        Args:
          base: A base address space to stack on top of (i.e. delegate to it for
            satisfying read requests).

          session: An optional session object.

          write: Should writing be allowed? Not currently implemented.

          profile: An optional profile to use for parsing the address space
            (e.g. needed for hibernation, crash etc.)
        """
        if session is None and base is not None:
            session = base.session

        self.base = base
        # This is the base address space which this address space reads from. In
        # this context, this address space is used to read physical addresses as
        # obtained from get_available_addresses().
        self.phys_base = self

        self.profile = profile
        self.session = session
        if session is None:
            raise RuntimeError("Session must be provided.")

        self.writeable = (
            self.session and self.session.writable_address_space or write)

        # This is a short lived cache. If we use a static image, this cache need
        # not expire, however, when analysing a live system we need to flush the
        # cache frequently.
        self.cache = utils.AgeBasedCache(max_age=20)

    def as_assert(self, assertion, error=None):
        """Duplicate for the assert command (so that optimizations don't disable
        them)

        It had to be called as_assert, since assert is a keyword
        """
        if not assertion:
            raise ASAssertionError(
                error or "Instantiation failed for unspecified reason")

    def describe(self, addr):
        """Return a string describing an address."""
        return "%#x" % addr

    def read(self, unused_addr, length):
        """Should be overridden by derived classes."""
        if length > self.session.GetParameter("buffer_size"):
            raise IOError("Too much data to read.")

        return "\x00" * length

    def get_available_addresses(self, start=0):
        """Generates address ranges (offset, phys_offset, size) for this AS.

        NOTE!! The phys_offset here refers to an address read from the phys_base
        member of this address space. I.e. it should be possible for callers to
        call get_available_addresses() and then directly get data via
        address_space.phys_base.read(phys_offset, length).

        Address ranges must be returned ordered.

        """
        _ = start
        return []

    def end(self):
        runs = list(self.get_available_addresses())
        if runs:
            return runs[-1][0] + runs[-1][2]

    def get_address_ranges(self, start=0, end=None):
        """Generates the address ranges which fall between start and end.

        Note that start and end are here specified in the virtual address
        space. More importantly this does not say anything about the pages in
        the physical address space - just because pages in the virtual address
        space are contiguous does not mean they are also contiguous in the
        physical address space.
        """
        if end is None:
            end = 0xfffffffffffff

        for voffset, poffset, length in self._get_address_ranges(
                start=start, end=end):
            # The entire range is below what is required - ignore it.
            if voffset + length < start:
                continue

            # The range starts after the address we care about - we are done.
            if voffset > end:
                return

            # Clip the bottom of the range to the start point, and the end of
            # the range to the end point.
            range_start = max(start, voffset)
            phys_range_start = poffset + range_start - voffset
            range_end = min(end, voffset + length)

            if range_end > range_start:
                yield range_start, phys_range_start, range_end - range_start

    def _get_address_ranges(self, start=0, end=None):
        """Generates merged address ranges from get_available_addresses()."""
        contiguous_voffset = 0
        contiguous_poffset = 0
        total_length = 0

        for (voffset, poffset, length) in self.get_available_addresses(
                start=start):

            if end and voffset > end:
                break

            # This can take some time as we enumerate all the address ranges.
            if self.session:
                self.session.report_progress(
                    "%(name)s: Merging Address Ranges %(spinner)s",
                    name=self.name)

            # Try to join up adjacent pages as much as possible.
            if (voffset == contiguous_voffset + total_length and
                    poffset == contiguous_poffset + total_length):
                total_length += length

            else:
                yield (contiguous_voffset, contiguous_poffset, total_length)

                # Reset the contiguous range.
                contiguous_voffset = voffset
                contiguous_poffset = poffset or 0
                total_length = length

        if total_length > 0:
            yield (contiguous_voffset, contiguous_poffset, total_length)

    def is_valid_address(self, _addr):
        """ Tell us if the address is valid """
        return True

    def write(self, addr, buf):
        try:
            return self.base.write(self.vtop(addr), buf)
        except AttributeError:
            raise NotImplementedError(
                "Write support for this type of Address Space"
                " has not been implemented")

    def vtop(self, addr):
        """Return the physical address of this virtual address."""
        # For physical address spaces, this is a noop.
        return addr

    @classmethod
    def metadata(cls, name, default=None):
        """Obtain metadata about this address space."""
        return getattr(cls, "_%s__%s" % (cls.__name__, name), default)

    def __str__(self):
        return self.__class__.__name__

    def __repr__(self):
        return "<%s @ %#x %s>" % (
            self.__class__.__name__, hash(self), self.name)

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self.base == other.base)


# This is a specialised AS for use internally - Its used to provide
# transparent support for a string buffer so types can be
# instantiated off the buffer.
class BufferAddressSpace(BaseAddressSpace):
    __abstract = True

    def __init__(self, base_offset=0, data='', **kwargs):
        super(BufferAddressSpace, self).__init__(**kwargs)
        self.fname = "Buffer"
        self.data = data
        self.base_offset = base_offset

    def assign_buffer(self, data, base_offset=0):
        self.base_offset = base_offset
        self.data = data

    def is_valid_address(self, addr):
        return not (addr < self.base_offset or addr > self.base_offset +
                    len(self.data))

    def read(self, addr, length):
        offset = addr - self.base_offset
        data = self.data[offset: offset + length]
        return data + "\x00" * (length - len(data))

    def write(self, addr, data):
        self.data = self.data[:addr] + data + self.data[addr + len(data):]
        return True

    def get_available_addresses(self, start=None):
        yield (self.base_offset, self.base_offset, len(self.data))

    def get_buffer_offset(self, offset):
        """Returns the offset in self.data for the virtual offset."""
        return offset - self.base_offset

    def __repr__(self):
        return "<%s @ %#x %s [%#X-%#X]>" % (
            self.__class__.__name__, hash(self), self.name,
            self.base_offset, self.end())

    def __len__(self):
        return len(self.data)

    def end(self):
        """Return the end address of the buffer."""
        return self.base_offset + len(self.data)


class CachingAddressSpaceMixIn(object):
    # The size of chunks we cache. This should be large enough to make file
    # reads efficient.
    CHUNK_SIZE = 32 * 1024
    CACHE_SIZE = 1000

    def __init__(self, **kwargs):
        super(CachingAddressSpaceMixIn, self).__init__(**kwargs)
        self._cache = utils.FastStore(self.CACHE_SIZE)

    def read(self, addr, length):
        addr, length = int(addr), int(length)

        result = ""
        while length > 0:
            data = self.read_partial(addr, length)
            if not data:
                break

            result += data
            length -= len(data)
            addr += len(data)

        return result

    def read_partial(self, addr, length):
        if addr == None:
            return addr

        chunk_number = addr / self.CHUNK_SIZE
        chunk_offset = addr % self.CHUNK_SIZE

        # Do not cache large reads.
        if chunk_offset == 0 and length > self.CHUNK_SIZE:
            return super(CachingAddressSpaceMixIn, self).read(
                addr, length)

        available_length = min(length, self.CHUNK_SIZE - chunk_offset)

        try:
            data = self._cache.Get(chunk_number)
        except KeyError:
            # Just read the data from the real class.
            data = super(CachingAddressSpaceMixIn, self).read(
                chunk_number * self.CHUNK_SIZE, self.CHUNK_SIZE)

            self._cache.Put(chunk_number, data)

        return data[chunk_offset:chunk_offset + available_length]


class PagedReader(BaseAddressSpace):
    """An address space which reads in page size.

    This automatically takes care of splitting a large read into smaller reads.
    """
    PAGE_SIZE = 0x1000
    __abstract = True

    def _read_chunk(self, vaddr, length):
        """
        Read bytes from a virtual address.

        Args:
          vaddr: A virtual address to read from.
          length: The number of bytes to read.

        Returns:
          As many bytes as can be read within this page.
        """
        to_read = min(length, self.PAGE_SIZE - (vaddr % self.PAGE_SIZE))
        paddr = self.vtop(vaddr)
        if paddr is None:
            return "\x00" * to_read

        return self.base.read(paddr, to_read)

    def read(self, addr, length):
        """
        Read 'length' bytes from the virtual address 'vaddr'.
        """
        if length > self.session.GetParameter("buffer_size"):
            raise IOError("Too much data to read.")

        addr, length = int(addr), int(length)

        result = ''

        while length > 0:
            buf = self._read_chunk(addr, length)
            if not buf:
                break

            result += buf
            addr += len(buf)
            length -= len(buf)

        return result

    def is_valid_address(self, addr):
        vaddr = self.vtop(addr)
        return vaddr != None and self.base.is_valid_address(vaddr)


class RunBasedAddressSpace(PagedReader):
    """An address space which uses a list of runs to specify a mapping."""

    # This is a list of (memory_offset, file_offset, length) tuples.
    runs = None
    __abstract = True

    def __init__(self, **kwargs):
        super(RunBasedAddressSpace, self).__init__(**kwargs)
        self.runs = utils.SortedCollection(key=lambda x: x[0])

        # Our get_available_addresses() refers to the base address space we
        # overlay on.
        self.phys_base = self.base

    def _read_chunk(self, addr, length):
        """Read from addr as much as possible up to a length of length."""
        file_offset, available_length = self._get_available_buffer(
            addr, length)

        # Mapping not valid. We need to pad until the next run.
        if file_offset is None:
            return "\x00" * min(length, available_length)

        else:
            return self.base.read(file_offset, min(length, available_length))

    def vtop(self, addr):
        file_offset, _ = self._get_available_buffer(addr, 1)
        return file_offset

    def _get_available_buffer(self, addr, length):
        """Resolves the address into the file offset.

        This function finds the run that contains this page and returns the file
        address where this page can be found.

        Returns:
          A tuple of (physical_offset, available_length). The
          physical_offset can be None to signify that the address is not
          valid. In this case the available_length signifies the number of
          bytes until the next available run.
        """
        addr = int(addr)
        try:
            virt_addr, file_address, file_length = self.runs.find_le(addr)
            available_length = file_length - (addr - virt_addr)
            physical_offset = addr - virt_addr + file_address

            if available_length > 0:
                return physical_offset, min(length, available_length)

        except ValueError:
            pass

        try:
            # Addr is outside any run, we need to find the next available
            # run and return the number of bytes we need to skip until then.
            virt_addr, _, _ = self.runs.find_ge(addr)

            return None, virt_addr - addr

        except ValueError:
            pass

        # A physical_offset of None means the address is not valid. If we get
        # here we dont have a next valid range.
        return None, 0xfffffffffffff

    def is_valid_address(self, addr):
        return self.vtop(addr) is not None

    def get_available_addresses(self, start=0):
        for run in self.runs:
            run_start, file_address, length = run[:3]
            if start > run_start + length:
                continue

            yield run_start, file_address, length

    def __eq__(self, other):
        return (super(RunBasedAddressSpace, self).__eq__(other) and
                self.runs == other.runs)


# TODO: Replace the RunBasedAddressSpace with this one since it is a super set.

class MultiRunBasedAddressSpace(PagedReader):
    """An address space which uses a list of runs to specify a mapping.

    This essentially delegates certain address ranges to other address spaces
    "mapped" into this address space.

    The runs are tuples of this form:

    (virtual_address, physical_address, length, address_space)

    - Virtual Address - An address in this address space's virtual address
      space.

    - Physical Address - An address in the delegate address space.

    - Length - The length of the mapped region.

    - Address space - the address space that should be read for this
      region. Note that the physical address above refers to addresses in this
      delegate address space.
    """

    # This is a list of (memory_offset, file_offset, length) tuples.
    runs = None
    __abstract = True

    def __init__(self, **kwargs):
        super(MultiRunBasedAddressSpace, self).__init__(**kwargs)
        self.runs = utils.SortedCollection(key=lambda x: x[0])

    def add_run(self, virt_addr, file_address, file_len, address_space):
        self.runs.insert((virt_addr, file_address, file_len, address_space))

    def _read_chunk(self, addr, length):
        """Read from addr as much as possible up to a length of length."""
        try:
            virt_addr, file_address, file_len, _as = self.runs.find_le(addr)
            available_length = file_len - (addr - virt_addr)
            physical_offset = addr - virt_addr + file_address

            if available_length > 0:
                return _as.read(physical_offset, min(length, available_length))

        except ValueError:
            pass

        try:
            # Addr is outside any run, we need to find the next available
            # run and return the number of bytes we need to pad until then.
            virt_addr, _, _, _ = self.runs.find_ge(addr)

            return "\x00" * min(length, virt_addr - addr)

        except ValueError:
            # If we get here we dont have a next valid range.
            return "\x00" * length

    def vtop(self, addr):
        """Returns the physical address for this virtual address.

        Note that this does not mean much without also knowing the address space
        to read from. Maybe we need to change this method prototype?
        """
        try:
            virt_addr, file_address, file_len, _ = self.runs.find_le(addr)
            available_length = file_len - (addr - virt_addr)
            physical_offset = addr - virt_addr + file_address

            if available_length > 0:
                return physical_offset

        except ValueError:
            pass

    def is_valid_address(self, addr):
        return self.vtop(addr) is not None

    # FIXME: Deprecate this method in all address spaces in favor of
    # get_mappings() below.
    def get_available_addresses(self, start=0):
        for run_start, file_address, length, _ in self.runs:
            if start > run_start + length:
                continue

            yield run_start, file_address, length

    def get_mappings(self, start=0):
        """Returns the mappings."""
        for run_start, file_address, length, _as in self.runs:
            if start > run_start + length:
                continue

            yield run_start, file_address, length, _as


class Error(Exception):
    """Address space errors."""


class ASAssertionError(Error, IOError, AssertionError):
    """The address space failed to instantiate."""


class AddrSpaceError(Error):
    """Address Space Exception.

    This exception is raised when an AS decides to not be instantiated. It is
    used in the voting algorithm.
    """

    def __init__(self):
        self.reasons = []
        Error.__init__(self, "No suitable address space mapping found")

    def append_reason(self, driver, reason):
        self.reasons.append((driver, reason))

    def __str__(self):
        result = Error.__str__(self) + "\nTried to open image as:\n"
        for k, v in self.reasons:
            result += " {0}: {1}\n".format(k, v)

        return result
