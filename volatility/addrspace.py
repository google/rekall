# Volatility
# Copyright (C) 2007,2008 Volatile Systems
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
from volatility import registry


class BaseAddressSpace(object):
    """ This is the base class of all Address Spaces. """

    __metaclass__ = registry.MetaclassRegistry
    __abstract = True

    order = 10

    def __init__(self, base=None, session=None, write=False, profile=None,
                 **kwargs):
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
        self.base = base
        self.profile = profile
        self.session = session
        self.writeable = (self.session and self.session.writable_address_space or
                          write)

    def as_assert(self, assertion, error = None):
        """Duplicate for the assert command (so that optimizations don't disable
        them)

        It had to be called as_assert, since assert is a keyword
        """
        if not assertion:
            raise ASAssertionError(error or
                                   "Instantiation failed for unspecified reason")

    def read(self, addr, length):
        """ Read some date from a certain offset """

    def zread(self, addr, length):
        data = self.read(int(addr), int(length))
        if not data:
            return "\x00" * length

        if len(data) < length:
            data += "\x00" * (length - len(data))

        return data

    def get_available_addresses(self):
        """Generates of address ranges as (offset, size) for by this AS."""
        return []

    def is_valid_address(self, _addr):
        """ Tell us if the address is valid """
        return True

    def write(self, _addr, _buf):
        raise NotImplementedError("Write support for this type of Address Space"
                                  " has not been implemented")

    def vtop(self, addr):
        """Return the physical address of this virtual address."""
        # For physical address spaces, this is a noop.
        return addr

    @classmethod
    def metadata(cls, name, default=None):
        """Obtain metadata about this address space."""
        prefix = '_md_'
        return getattr(cls, prefix + name, default)

    def __str__(self):
        return self.__class__.__name__


class DummyAddressSpace(BaseAddressSpace):
    """An AS which always returns nulls."""
    __name = 'dummy'
    __abstract = True

    def is_valid_address(self, _offset):
        return True

    def read(self, _offset, length):
        return '0x00' * length


class AbstractVirtualAddressSpace(BaseAddressSpace):
    """Base Ancestor for all Virtual address spaces, as determined by astype"""
    __abstract = True

    def __init__(self, astype = 'virtual', **kwargs):
        super(AbstractVirtualAddressSpace, self).__init__(**kwargs)
        self.astype = astype

        self.as_assert(self.astype == 'virtual' or self.astype == 'any',
                       "User requested non-virtual AS")

    def vtop(self, vaddr):
        raise NotImplementedError("This is a virtual class and should not be "
                                  "referenced directly")


## This is a specialised AS for use internally - Its used to provide
## transparent support for a string buffer so types can be
## instantiated off the buffer.
class BufferAddressSpace(BaseAddressSpace):
    __abstract = True

    def __init__(self, base_offset = 0, data = '', **kwargs):
        self.fname = "Buffer"
        self.data = data
        self.base_offset = base_offset

    def assign_buffer(self, data, base_offset = 0):
        self.base_offset = base_offset
        self.data = data

    def is_valid_address(self, addr):
        return not (addr < self.base_offset or addr > self.base_offset +
                    len(self.data))

    def read(self, addr, length):
        offset = addr - self.base_offset
        return self.data[offset: offset + length]

    def write(self, addr, data):
        self.data = self.data[:addr] + data + self.data[addr + len(data):]
        return True

    def get_available_addresses(self):
        yield (self.base_offset, len(self.data))


class PagedReader(BaseAddressSpace):
    """An address space which reads in page size.

    This automatically takes care of splitting a large read into smaller reads.
    """
    PAGE_SIZE = 0x1000
    __abstract = True

    def _read_chunk(self, vaddr, length, pad=False):
        """
        Read bytes from a virtual address.

        Args:
          vaddr: A virtual address to read from.
          length: The number of bytes to read.
          pad: If set, pad unavailable data with nulls.

        Returns:
          As many bytes as can be read within this page, or a NoneObject() if we
          are not padding and the address is invalid.
        """
        to_read = min(length, self.PAGE_SIZE - (vaddr % self.PAGE_SIZE))
        paddr = self.vtop(vaddr)
        if paddr is None:
            if pad:
                return "\x00" * to_read
            else:
                return None

        return self.base.read(paddr, to_read)

    def _read_bytes(self, vaddr, length, pad):
        """
        Read 'length' bytes from the virtual address 'vaddr'.
        The 'pad' parameter controls whether unavailable bytes
        are padded with zeros.
        """
        vaddr, length = int(vaddr), int(length)

        result = ''

        while length > 0:
            buf = self._read_chunk(vaddr, length, pad=pad)
            if not buf: break

            result += buf
            vaddr += len(buf)
            length -= len(buf)

        return result

    def read(self, vaddr, length):
        '''
        Read and return 'length' bytes from the virtual address 'vaddr'.
        If any part of that block is unavailable, return None.
        '''
        return self._read_bytes(vaddr, length, pad = False)

    def zread(self, vaddr, length):
        '''
        Read and return 'length' bytes from the virtual address 'vaddr'.
        If any part of that block is unavailable, pad it with zeros.
        '''
        return self._read_bytes(vaddr, length, pad = True)

    def is_valid_address(self, addr):
        vaddr = self.vtop(addr)
        return self.base.is_valid_address(vaddr)

    def get_available_addresses(self):
        for start, length in self.get_available_pages():
            yield start * self.PAGE_SIZE, length * self.PAGE_SIZE


class Error(Exception):
    """Address space errors."""


class ASAssertionError(Error):
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

