# This module provides for a central knowledge base which plugins can use to
# collect information.

import bisect
import logging
import re

from rekall import obj
from rekall import registry


class SymbolContainer(object):
    """A container class for symbols."""


class SortedAddresses(object):
    """An object to abstract searching for known memory locations."""

    def __init__(self):
        self._data = []
        self._map = {}

    def AddMemoryLocation(self, offset, data):
        """Adds the data to the memory offset."""
        bisect.insort_right(self._data, offset)
        self._map.setdefault(offset, []).append(data)

    def GetSpan(self, offset):
        """Gets the next lowest and next highest data below the offset."""
        idx = bisect.bisect_left(self._data, offset)

        if idx == 0:
            lowest = None
        else:
            lowest = self._map.get(self._data[idx - 1])

        if idx == len(self._data):
            highest = None
        else:
            highest = self._map.get(self._data[idx])

        return lowest, highest


class SymbolAddresses(SortedAddresses):

    def __init__(self):
        super(SymbolAddresses, self).__init__()
        self.symbols = SymbolContainer()

    def AddMemoryLocation(self, offset, func):
        """Add the function object to the list."""
        super(SymbolAddresses, self).AddMemoryLocation(offset, func)

        try:
            module_name, func_name = func.obj_name.split(":")
            module_name = re.match("[_a-zA-Z0-9]+", module_name).group(0)
            func_name = re.match("[_a-zA-Z0-9]+", func_name).group(0)

            module = getattr(self.symbols, module_name, None)
            if module is None:
                module = SymbolContainer()
                setattr(self.symbols, module_name, module)

            setattr(module, func_name, offset)

        except (ValueError, AttributeError):
            pass


class ParameterHook(object):
    """A mechanism for automatically calculating a parameter.

    The session contains many parameters which are calculated through the
    various plugins, or provided by the user. These parameters essentially
    represent a growing body of knowledge about the image we are currently
    analysing.

    Some plugins require this information before they can continue. If the
    information is already known, we do not need to re-derive it, and the value
    can be cached in the session.

    A ParameterHook is a class which is called to find out the value of a
    parameter when it is not known.
    """
    __abstract = True

    __metaclass__ = registry.MetaclassRegistry

    # The name of the parameter we will be calculating. This class will
    # automatically be called when someone accessed this name, and it is not
    # already known.
    name = None

    # The number of seconds this parameter can be assumed valid - or None if the
    # parameter does not expire. NOTE that expiry is only considered in the
    # physical_address_space.metadata("live") == True.
    expiry = None

    @classmethod
    def is_active(cls, session):
        _ = session
        return True

    def __init__(self, session):
        self.session = session

    def calculate(self):
        """Derive the value of the parameter."""


class AddressResolver(object):
    """Wrapper around a profile which allows addresses to be resolved in it."""

    # The format of a symbol name. Used by get_address_by_name().
    ADDRESS_NAME_REGEX = re.compile(
        "([^!]+)!([^ ]+)?(( *[+-] *)([0-9a-fA-Fx]+))?")

    def __init__(self, session):
        self.profiles = {}
        self.modules = None
        self.modules_by_name = {}
        self.session = session

    def _EnsureInitialized(self):
        if self.modules is None:
            try:
                self.modules = self.session.plugins.modules()
                for module in self.modules.lsmod():
                    self.modules_by_name[module.name] = module

            except AttributeError:
                self.modules = None

    def LoadProfileForModule(self, module):
        if module:
            if module.name in self.profiles:
                return self.profiles[module.name]

            try:
                module_profile = self.session.LoadProfile(
                    "GUID/%s" % module.RSDS.GUID_AGE)
                module_profile.image_base = module.base
                self.profiles[module.name] = module_profile

                return module_profile
            except ValueError:
                # Cache the fact that we did not find this profile.
                self.profiles[module.name] = None

                logging.debug("Unable to resolve symbols in module %s",
                              module.name)

    def get_address_by_name(self, name):
        self._EnsureInitialized()

        if not isinstance(name, basestring):
            raise TypeError("Name should be a string.")

        # Can be represented as hex.
        if name.startswith("0x"):
            return int(name, 16)

        m = self.ADDRESS_NAME_REGEX.match(name)
        if m:
            module_name = m.group(1)
            symbol = m.group(2)

            module = self.modules_by_name[module_name]
            if symbol:
                module_profile = self.LoadProfileForModule(module)
                address = module_profile.get_constant(symbol, True)
            else:
                address = module.base

            if m.group(3):
                operator = m.group(4).strip()
                offset = self.get_address_by_name(m.group(5))
                if operator == "+":
                    address += offset
                else:
                    address -= offset

            return address

        # name can be just a straight forward integer.
        return int(name)

    def get_constant_by_address(self, address):
        self._EnsureInitialized()

        address = obj.Pointer.integer_to_address(address)
        if self.modules:
            containing_module = self.modules.find_module(address)
            module_profile = self.LoadProfileForModule(containing_module)

            return module_profile.get_constant_by_address(address)

    def get_nearest_constant_by_address(self, address):
        self._EnsureInitialized()

        address = obj.Pointer.integer_to_address(address)
        nearest_offset = 0
        module_name = nearest_name = ""
        profile = None

        # Find the containing module and see if we have a profile for it.
        if self.modules:
            containing_module = self.modules.find_module(address)
            if containing_module:
                nearest_offset = containing_module.base
                module_name = containing_module.name

                # Try to load the module profile.
                profile = self.LoadProfileForModule(containing_module)
                if profile:
                    offset, name = profile.get_nearest_constant_by_address(
                        address)

                    if address - offset < address - nearest_offset:
                        nearest_offset = offset
                        nearest_name = name

        if module_name:
            full_name = "%s!%s" % (module_name, nearest_name)
        else:
            full_name = ""

        return nearest_offset, full_name
