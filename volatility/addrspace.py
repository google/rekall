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

#pylint: disable-msg=C0111
import volatility.registry as registry
import volatility.debug as debug
from volatility import conf

config = conf.ConfFactory()


class BaseAddressSpace(object):
    """ This is the base class of all Address Spaces. """

    __metaclass__ = registry.MetaclassRegistry
    __abstract = True

    def __init__(self, base=None, config=None, **_kwargs):
        """ base is the AS we will be stacking on top of, opts are
        options which we may use.
        """
        self.base = base
        self._config = config

    @staticmethod
    def register_options(config):
        """This method should declare the options required for this address
        space to exit. It is recommended that these options also be accepted
        through the **kwargs in the constructor, so the address space can be
        instantiated programmatically.
        """

    def get_config(self):
        """Returns the config object used by the vm for use in other vms"""
        return self._config

    def as_assert(self, assertion, error = None):
        """Duplicate for the assert command (so that optimizations don't disable them)

           It had to be called as_assert, since assert is a keyword
        """
        if not assertion:
            if error == None:
                error = "Instantiation failed for unspecified reason"
            raise ASAssertionError, error

    def read(self, addr, length):
        """ Read some date from a certain offset """

    def get_available_addresses(self):
        """ Return a generator of address ranges as (offset, size) covered by this AS """
        raise StopIteration

    def is_valid_address(self, _addr):
        """ Tell us if the address is valid """
        return True

    def write(self, _addr, _buf):
        if not self._config.WRITE:
            return False
        raise NotImplementedError("Write support for this type of Address Space has not been implemented")



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

    def __init__(self, base, config, astype = 'virtual', *args, **kwargs):
        BaseAddressSpace.__init__(self, base, config, astype = astype, *args, **kwargs)
        self.as_assert(astype == 'virtual' or astype == 'any', "User requested non-virtual AS")

    def vtop(self, vaddr):
        raise NotImplementedError("This is a virtual class and should not be referenced directly")

## This is a specialised AS for use internally - Its used to provide
## transparent support for a string buffer so types can be
## instantiated off the buffer.
class BufferAddressSpace(BaseAddressSpace):
    __abstract = True

    def __init__(self, config=None, base_offset = 0, data = '', **kwargs):
        BaseAddressSpace.__init__(self, base=None, config=None, **kwargs)
        self.fname = "Buffer"
        self.data = data
        self.base_offset = base_offset

    def assign_buffer(self, data, base_offset = 0):
        self.base_offset = base_offset
        self.data = data

    def is_valid_address(self, addr):
        return not (addr < self.base_offset or addr > self.base_offset + len(self.data))

    def read(self, addr, length):
        offset = addr - self.base_offset
        return self.data[offset: offset + length]

    def write(self, addr, data):
        if not self._config.WRITE:
            return False
        self.data = self.data[:addr] + data + self.data[addr + len(data):]
        return True

    def get_available_addresses(self):
        yield (self.base_offset, len(self.data))



class Error(Exception):
    """Address space errors."""


class ASAssertionError(Error):
    """The address space failed to instantiate."""


class AddrSpaceError(Error):
    """Address Space Exception, so we can catch and deal with it in the main program"""

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


def GuessAddressSpace(config, astype = 'virtual', **kwargs):
    """Loads an address space by stacking valid ASes on top of each other (priority order first)"""
    base_as = obj.NoneObject("Address space not found.")

    # Register all the parameters of all address spaces since we are going to
    # try them all.
    for cls in BaseAddressSpace.classes.values():
        cls.register_options(config)
    config.parse_options()

    error = AddrSpaceError()
    while 1:
        debug.debug("Voting round")
        found = False
        for cls in BaseAddressSpace.classes.values():
            debug.debug("Trying {0} ".format(cls))
            try:
                base_as = cls(base_as, config, astype=astype, **kwargs)
                debug.debug("Succeeded instantiating {0}".format(base_as))
                found = True
                break
            except ASAssertionError, e:
                debug.debug("Failed instantiating {0}: {1}".format(cls.__name__, e), 2)
                error.append_reason(cls.__name__, e)
                continue
            except Exception, e:
                debug.debug("Failed instantiating (exception): {0}".format(e))
                error.append_reason(cls.__name__ + " - EXCEPTION", e)
                continue

        ## A full iteration through all the classes without anyone
        ## selecting us means we are done:
        if not found:
            break

    return base_as


def AddressSpaceFactory(config = None, specification = '', astype = 'virtual', **kwargs):
    """Build the address space from the specification.

    Args:
       config: A ConfigObject.
       specification: A column separated list of AS class names to be stacked.
    """
    base_as = None
    for as_name in specification.split(":"):
        as_cls = BaseAddressSpace.classes.get(as_name)
        if as_cls is None:
            raise Error("No such address space %s" % as_name)

        base_as = as_cls(base_as, config=config, astype = astype, **kwargs)

    return base_as

def PAddressSpaceCallback(_option, _opt_str, specification, parser):
    """Create a physical address space from a specification."""
    try:
        config.readonly["physical_address_space"] = AddressSpaceFactory(
            config, specification,  astype = 'physical')
    except KeyError:
        # This is only an error on the final pass.
        if parser.final:
            raise Error("Invalid address space specification %s" % specification)


def VAddressSpaceCallback(_option, _opt_str, specification, parser):
    """Create a virtual address space from a specification."""
    try:
        config.readonly["virtual_address_space"] = AddressSpaceFactory(
            config, specification,  astype = 'virtual')
    except KeyError:
        # This is only an error on the final pass.
        if parser.final:
            raise Error("Invalid address space specification %s" % specification)


## By default load the profile that the user asked for
config.add_option("PHYSICAL_ADDRESS_SPACE", default = None, action = "callback",
                  callback = PAddressSpaceCallback, type=str,
                  nargs = 1, help = "Specifies how to Create the physical address space (Guess by default).")

## By default load the profile that the user asked for
config.add_option("VIRTUAL_ADDRESS_SPACE", default = None, action = "callback",
                  callback = VAddressSpaceCallback, type=str,
                  nargs = 1, help = "Specifies how to Create the virtual address space (Guess by default).")
