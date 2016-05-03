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


class Zeroer(object):
    def __init__(self):
        self.store = utils.FastStore(10, lock=True)

    def GetZeros(self, length):
        try:
            return self.store.Get(length)
        except KeyError:
            zeros = "\x00" * length
            self.store.Put(length, zeros)
            return zeros


# Keep a bunch of zeros around for speed.
ZEROER = Zeroer()


class TranslationLookasideBuffer(object):
    """An implementation of a TLB.

    This can be used by an address space to cache translations.
    """

    PAGE_SHIFT = 12
    PAGE_ALIGNMENT = (1 << PAGE_SHIFT) - 1
    PAGE_MASK = ~ PAGE_ALIGNMENT

    def __init__(self, max_size=10):
        self.page_cache = utils.FastStore(max_size)

    def Get(self, vaddr):
        """Returns the cached physical address for this virtual address."""

        # The cache only stores page aligned virtual addresses. We add the page
        # offset to the physical addresses automatically.
        result = self.page_cache.Get(vaddr & self.PAGE_MASK)

        # None is a valid cached value, it means no mapping exists.
        if result is not None:
            return result + (vaddr & self.PAGE_ALIGNMENT)

    def Put(self, vaddr, paddr):
        if vaddr & self.PAGE_ALIGNMENT:
            raise TypeError("TLB must only cache aligned virtual addresses.")

        self.page_cache.Put(vaddr, paddr)


class Run(object):
    """A container for runs."""
    __slots__ = ("start", "end", "address_space", "file_offset", "data")

    def __init__(self, start=None, end=None, address_space=None,
                 file_offset=None, data=None):
        self.start = start
        self.end = end
        self.address_space = address_space
        self.file_offset = file_offset
        self.data = data

    @utils.safe_property
    def length(self):
        return self.end - self.start

    @length.setter
    def length(self, value):
        self.end = self.start + value

    def copy(self, **kw):
        kwargs = dict(start=self.start, end=self.end,
                      address_space=self.address_space,
                      file_offset=self.file_offset,
                      data=self.data)
        kwargs.update(kw)

        return self.__class__(**kwargs)

    def __str__(self):
        if self.file_offset is None:
            return u"<%#x, %#x>" % (self.start, self.end)

        return u"<%#x, %#x> -> %#x @ %s" % (
            self.start, self.end, self.file_offset,
            self.address_space)


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

    # This flag signifies whether this address space's contents are likely to
    # change between reads. If an address space is NOT volatile (this flag is
    # False) then reads from the same offset MUST always return the same bytes.
    volatile = False

    # This flag signifies whether this address space is for a virtual machine.
    virtualized = False

    def __init__(self, base=None, session=None, profile=None, **_):
        """Base is the AS we will be stacking on top of, opts are options which
        we may use.

        Args:
          base: A base address space to stack on top of (i.e. delegate to it for
              satisfying read requests).

          session: An optional session object.

          profile: An optional profile to use for parsing the address space
              (e.g. needed for hibernation, crash etc.)
        """
        if session is None and base is not None:
            session = base.session

        self.base = base
        if base:
            self.volatile = self.base.volatile

        self.profile = profile
        self.session = session
        if session is None:
            raise RuntimeError("Session must be provided.")

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

        return ZEROER.GetZeros(length)

    def get_mappings(self, start=0, end=2**64):
        """Generates a sequence of Run() objects.

        Each Run object describes a single range transformation from this
        address space to another address space at a potentially different
        mapped_offset.

        Runs are assumed to not overlap and are generated in increasing order.

        Args:
          start: The suggested start address we are interested in. This function
              may omit runs that lie entirely below this start address. Note:
              Runs are not adjusted to begin at the start address - it may be
              possible that this method returns a run which starts earlier than
              the specified start address.
        """
        _ = start
        _ = end
        return []

    def end(self):
        runs = list(self.get_mappings())
        if runs:
            last_run = runs[-1]
            return last_run.end

    def get_address_ranges(self, start=0, end=0xfffffffffffff):
        """Generates the runs which fall between start and end.

        Note that start and end are here specified in the virtual address
        space. More importantly this does not say anything about the pages in
        the physical address space - just because pages in the virtual address
        space are contiguous does not mean they are also contiguous in the
        physical address space.

        Yields:
          Run objects describing merged virtual address ranges. NOTE: These runs
          do not have file_offset or address_space members since the file_offset
          is not the same across the entire range and therefore it does not make
          sense to directly read the base address space - If you want to do
          this, use merge_base_ranges() instead.
        """
        last_voffset = last_voffset_end = 0

        for run in self.get_mappings(start=start, end=end):
            # No more runs apply.
            if run.start > end:
                break

            if run.start < start:
                # We dont care about the file_offset here since it will be
                # dropped later.
                run = run.copy(start=start)

            # This can take some time as we enumerate all the address ranges.
            self.session.report_progress(
                "%(name)s: Merging Address Ranges %(offset)#x %(spinner)s",
                offset=run.start, name=self.name)

            # Extend the last range if this range starts at the end of the last
            # one.
            if run.start == last_voffset_end:
                last_voffset_end = run.end

            else:
                # Emit the last range
                if last_voffset_end > last_voffset:
                    yield Run(start=last_voffset,
                              end=last_voffset_end)

                # Reset the contiguous range.
                last_voffset = run.start
                last_voffset_end = min(run.end, end)

        if last_voffset_end > last_voffset:
            yield Run(start=last_voffset, end=last_voffset_end)

    def merge_base_ranges(self, start=0, end=0xfffffffffffff):
        """Generates merged address ranges from get_mapping().

        This method is subtly different from get_address_ranges in that runs are
        contiguous in the base address space, hence the yielded runs have a
        valid file_offset member. Callers can safely issue read operations to
        the address space.

        Yields:
          runs which are contiguous in the base address space. This function
            is designed to produce ranges more optimized for reducing the number
            of read operations from the underlying base address space.

        """
        contiguous_voffset = 0
        contiguous_voffset_end = 0
        contiguous_poffset = 0
        last_run_length = 0
        last_as = None

        for run in self.get_mappings(start=start, end=end):
            # No more runs apply.
            if end and run.start > end:
                break

            if run.start < start:
                run = run.copy(
                    start=start,
                    file_offset=run.file_offset + start - run.start)

            # This can take some time as we enumerate all the address ranges.
            self.session.report_progress(
                "%(name)s: Merging Address Ranges %(offset)#x %(spinner)s",
                offset=run.start, name=self.name)

            # Try to join up adjacent pages as much as possible.
            if (run.start == contiguous_voffset_end and
                    run.file_offset == contiguous_poffset + last_run_length and
                    run.address_space is last_as):
                contiguous_voffset_end = min(run.end, end)
                last_run_length = contiguous_voffset_end - contiguous_voffset
                last_as = run.address_space

            else:
                if last_run_length > 0:
                    yield Run(start=contiguous_voffset,
                              end=contiguous_voffset_end,
                              address_space=last_as,
                              file_offset=contiguous_poffset)

                # Reset the contiguous range.
                contiguous_voffset = run.start
                contiguous_voffset_end = min(run.end, end)
                contiguous_poffset = run.file_offset or 0
                last_run_length = contiguous_voffset_end - contiguous_voffset
                last_as = run.address_space

        if last_run_length > 0:
            yield Run(start=contiguous_voffset,
                      end=contiguous_voffset_end,
                      address_space=last_as,
                      file_offset=contiguous_poffset)

    def is_valid_address(self, _addr):
        """Tell us if the address is valid """
        return True

    def write(self, addr, buf):
        """Write to the address space, if writable.

        The default behavior is to delegate the write to the base address space.
        If an address space has no base then this function will throw an
        IOError. Address spaces that actually implement writing should override.

        Raises:
            IOError if there is no base address space. Subclasses may raise
                under additional circumstances.

        Arguments:
            addr: The address to write at, as understood by this AS (i.e.
                a virtual address for virtual address spaces, physical for
                physical).
            buf: The data to write - most commonly a basestring instance.

        Returns:
            Number of bytes written.
        """
        if not self.base:
            raise IOError("No base address space set on %r." % self)

        return self.base.write(self.vtop(addr), buf)

    def vtop(self, addr):
        """Return the physical address of this virtual address."""
        # For physical address spaces, this is a noop.
        return addr

    def vtop_run(self, addr):
        """Returns a Run object describing where addr can be read from."""
        return Run(start=addr,
                   end=addr,
                   address_space=self,
                   file_offset=addr)

    @classmethod
    def metadata(cls, name, default=None):
        """Obtain metadata about this address space."""
        return getattr(cls, "_%s__%s" % (cls.__name__, name), default)

    def __unicode__(self):
        return self.__class__.__name__

    def __str__(self):
        return utils.SmartStr(self)

    def __repr__(self):
        return "<%s @ %#x %s>" % (
            self.__class__.__name__, hash(self), self.name)

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self.base == other.base)

    def get_file_address_space(self, filename):
        """Implement this to return an address space for filename."""

    def get_mapped_offset(self, filename, offset):
        """Implement this if we can map files into this address space."""

    def ConfigureSession(self, session_obj):
        """Implement this method if you need to configure the session."""

    def close(self):
        pass


class BufferAddressSpace(BaseAddressSpace):
    """Specialized address space for internal use.

    Provides transparent reads through to a string buffer, so that profile
    types can be instantiated on top of strings.
    """
    __image = False

    @utils.safe_property
    def writable(self):
        """Buffer AS is always writable, no matter what the session says."""
        return True

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
        return data + ZEROER.GetZeros(length - len(data))

    def write(self, addr, data):
        if addr > len(self.data):
            raise ValueError(
                "Cannot write to offset %d of buffer with size %d." %
                (addr, len(self.data)))
        self.data = self.data[:addr] + data + self.data[addr + len(data):]
        return len(data)

    def get_mappings(self, start=None, end=2**64):
        if self.end > start and self.end < end:
            yield Run(start=self.base_offset,
                      end=self.end,
                      file_offset=self.base_offset,
                      address_space=self)

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
    CACHE_SIZE = 10

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

    def cached_read_partial(self, addr, length):
        """Implement this to allow the caching mixin to cache these reads."""
        # By default call the next read_partial in the inheritance tree.
        return super(CachingAddressSpaceMixIn, self).read(addr, length)

    def read_partial(self, addr, length):
        if addr == None:
            return addr

        chunk_number = addr / self.CHUNK_SIZE
        chunk_offset = addr % self.CHUNK_SIZE

        # Do not cache large reads but still pad them to CHUNK_SIZE.
        if chunk_offset == 0 and length > self.CHUNK_SIZE:
            # Deliberately do a short read to avoid copying.
            to_read = length - length % self.CHUNK_SIZE
            return self.cached_read_partial(addr, to_read)

        available_length = min(length, self.CHUNK_SIZE - chunk_offset)

        try:
            data = self._cache.Get(chunk_number)
        except KeyError:
            # Just read the data from the real class.
            data = self.cached_read_partial(
                chunk_number * self.CHUNK_SIZE, self.CHUNK_SIZE)

            self._cache.Put(chunk_number, data)

        return data[chunk_offset:chunk_offset + available_length]


class PagedReader(BaseAddressSpace):
    """An address space which reads in page size.

    This automatically takes care of splitting a large read into smaller reads.
    """
    PAGE_SIZE = 0x1000
    PAGE_MASK = ~(PAGE_SIZE - 1)
    __abstract = True

    def _read_chunk(self, vaddr, length):
        """Read bytes from a virtual address.

        Args:
          vaddr: A virtual address to read from.
          length: The number of bytes to read.

        Returns:
          As many bytes as can be read within this page.
        """
        to_read = min(length, self.PAGE_SIZE - (vaddr % self.PAGE_SIZE))
        paddr = self.vtop(vaddr)
        if paddr is None:
            return ZEROER.GetZeros(to_read)

        return self.base.read(paddr, to_read)

    def _write_chunk(self, vaddr, buf):
        to_write = min(len(buf), self.PAGE_SIZE - (vaddr % self.PAGE_SIZE))
        if not to_write:
            return 0

        paddr = self.vtop(vaddr)
        if not paddr:
            return 0

        return self.base.write(paddr, buf[:to_write])

    def write(self, addr, buf):
        available = len(buf)
        written = 0

        while available > written:
            chunk_len = self._write_chunk(addr + written, buf[written:])
            if not chunk_len:
                break
            written += chunk_len

        return written

    def read(self, addr, length):
        """Read 'length' bytes from the virtual address 'vaddr'."""
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
        super(RunBasedAddressSpace, self).__init__(**kwargs)
        self.runs = utils.RangedCollection()

    def add_run(self, virt_addr, file_address, file_len, address_space=None,
                data=None):
        """Add a new run to this address space."""
        if address_space is None:
            address_space = self.base

        start = virt_addr  # Range start
        end = virt_addr + file_len  # Range end

        self.runs.insert(start, end,
                         Run(start=start,
                             end=end,
                             address_space=address_space,
                             file_offset=file_address,
                             data=data))

    def _read_chunk(self, addr, length):
        """Read from addr as much as possible up to a length of length."""
        start, end, run = self.runs.get_containing_range(addr)

        # addr is not in any range, pad to the next range.
        if start is None:
            end = self.runs.get_next_range_start(addr)
            if end is None:
                end = addr + length

            return ZEROER.GetZeros(min(end - addr, length))

        # Read as much as we can from this address space.
        available_length = min(end - addr, length)
        file_offset = run.file_offset + addr - start

        return run.address_space.read(file_offset, available_length)

    def _write_chunk(self, addr, buf):
        length = len(buf)
        start, end, run = self.runs.get_containing_range(addr)

        # addr is not in any range, ignore to the next range.
        if start is None:
            end = self.runs.get_next_range_start(addr)
            if end is None:
                end = addr + length

            return min(end - addr, length)

        # Write as much as we can to this run.
        available_length = min(end - addr, length)
        file_offset = run.file_offset + addr - start

        return run.address_space.write(file_offset, buf[:available_length])

    def vtop_run(self, addr):
        start, _, run = self.runs.get_containing_range(addr)
        if start is not None:
            return Run(start=addr,
                       end=run.end,
                       address_space=run.address_space,
                       file_offset=run.file_offset + addr - run.start)

    def vtop(self, addr):
        """Returns the physical address for this virtual address.

        Note that this does not mean much without also knowing the address space
        to read from. Maybe we need to change this method's prototype?
        """
        start, end, run = self.runs.get_containing_range(addr)
        if start is not None:
            if addr < end:
                return run.file_offset + addr - start

    def is_valid_address(self, addr):
        return self.vtop(addr) is not None

    def get_mappings(self, start=0, end=2**64):
        """Yields the mappings.

        Yields: A seqence of Run objects representing each run.
        """
        for _, _, run in self.runs:
            if start > run.end:
                continue

            if run.start > end:
                return

            yield run


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
