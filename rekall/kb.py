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
        r"(?P<module>[A-Za-z0-9\.]+)"   # Module name - can include extension
                                        # (.exe, .sys)

        r"!?"                           # ! separates module name from symbol
                                        # name.

        r"(?P<symbol>[^ +-]+)?"         # Symbol name.
        r"(?P<op> *[+-] *)?"            # Possible arithmetic operator.
        r"(?P<offset>[0-9a-fA-Fx]+)?")  # Possible hex offset.

    def __init__(self, session):
        self.session = session
        self.profiles = {}
        self.Reset()

    def _NormalizeModuleName(self, module):
        try:
            module_name = module.name
        except AttributeError:
            module_name = module

        result = unicode(module_name).split(".")[0]
        if result == "ntoskrnl":
            result = "nt"

        return result.lower()

    def _ParseAddress(self, name):
        m = self.ADDRESS_NAME_REGEX.match(name)
        if m:
            capture = m.groupdict()
            module = capture.get("module")
            if not module:
                raise TypeError("Module name not specified.")

            capture["module"] = self._NormalizeModuleName(module)

            if capture["op"] and not capture["offset"]:
                raise TypeError("Operator %s must have an operand." %
                                capture["op"])

            if capture["op"] and not capture["symbol"]:
                raise TypeError("Operator %s must operate on a symbol." %
                                capture["op"])

            return capture

        raise TypeError("Unable to parse %r as a symbol name" % name)

    def _FindContainingModule(self, address):
        if self.modules:
            return self.modules.find_module(address)

    def GetState(self):
        return dict(modules=self.modules,
                    modules_by_name=self.modules_by_name,
                    profiles=self.profiles)

    def SetState(self, state):
        self.modules = state["modules"]
        self.modules_by_name = state["modules_by_name"]
        self.profiles = state["profiles"]

    def Reset(self):
        """Flush all caches and reset the resolver."""
        self.modules = None
        self.modules_by_name = {}
        self.profiles = {}

    def get_constant_object(self, name, target, **kwargs):
        """Instantiate the named constant with these args."""
        self._EnsureInitialized()

        profile = self.LoadProfileForName(name)
        if profile:
            components = self._ParseAddress(name)
            if not components["symbol"]:
                raise ValueError("No symbol name specified.")

            return profile.get_constant_object(
                components["symbol"],
                target=target, **kwargs)

        return obj.NoneObject("Profile for name %s unknown.", name, log=True)

    def _EnsureInitialized(self):
        if self.modules is None:
            try:
                self.modules = self.session.plugins.modules()
                for module in self.modules.lsmod():
                    module_name = self._NormalizeModuleName(module)
                    self.modules_by_name[module_name] = module

                    # Update the image base of our profiles.
                    if module_name in self.profiles:
                        self.profiles[module_name].image_base = module.base

            except AttributeError:
                self.modules = None

    def _LoadProfile(self, module_name, profile):
        self._EnsureInitialized()
        try:
            module_name = self._NormalizeModuleName(module_name)
            module = self.modules_by_name[module_name]

            module_profile = self.session.LoadProfile(profile)
            module_profile.image_base = module.base

            # Merge in the kernel profile into this profile.
            module_profile.merge(self.session.profile)

            self.profiles[module_name] = module_profile

            return module_profile
        except ValueError:
            # Cache the fact that we did not find this profile.
            self.profiles[module_name] = None

            logging.debug("Unable to resolve symbols in module %s",
                          module_name)

    def LoadProfileForModule(self, module):
        self._EnsureInitialized()
        result = None
        module_base = module.base

        module_name = self._NormalizeModuleName(module)
        if module_name in self.profiles:
            return self.profiles[module_name]

        guid = module.RSDS.GUID_AGE
        if guid:
            result = self._LoadProfile(module_name, "GUID/%s" % guid)

        if not result:
            # Create a dummy profile.
            result = obj.Profile.classes["BasicPEProfile"](
                name="Dummy Profile %s" % module_name,
                session=self.session)
            result.image_base = module_base

        peinfo = self.session.plugins.peinfo(image_base=module_base,
                                             address_space=module.obj_vm)

        constants = {}
        for _, func, name, _ in peinfo.pe_helper.ExportDirectory():
            self.session.report_progress("Merging export table: %s", name)
            func_offset = func.v()
            if not result.get_constant_by_address(func_offset):
                constants[str(name)] = func_offset - module_base

        result.add_constants(constants_are_addresses=True, **constants)

        self.profiles[module_name] = result

        return result

    def LoadProfileForName(self, name):
        """Returns the profile responsible for the symbol name."""
        if not isinstance(name, basestring):
            raise TypeError("Name should be a string.")

        self._EnsureInitialized()

        components = self._ParseAddress(name)
        module_name = components["module"]

        # See if the user has specified the profile in the session cache.
        profile = self.session.GetParameter("%s_profile" % module_name)
        if profile:
            return self._LoadProfile(module_name, profile)

        # Try to detect the GUI from the module object.
        module = self.modules_by_name[module_name]
        return self.LoadProfileForModule(module)

    def get_address_by_name(self, name):
        self._EnsureInitialized()

        try:
            return int(name)
        except ValueError:
            pass

        if not isinstance(name, basestring):
            raise TypeError("Name should be a string.")

        # Name can be represented as hex or integer.
        try:
            return int(name, 0)
        except ValueError:
            pass

        components = self._ParseAddress(name)
        address = None

        module = self.modules_by_name.get(components["module"])
        if module is None:
            return obj.NoneObject("No module %s" % name, log=True)

        # User is after just the module's base address.
        if not components["symbol"]:
            return module.base

        # Search for a symbol in the module.
        if components["symbol"]:
            # Get the profile for this module.
            module_profile = self.LoadProfileForModule(module)
            if module_profile:
                address = module_profile.get_constant(
                    components["symbol"], True)

                # Support basic offset operations (+/-).
                if components["op"]:
                    offset = int(components["offset"], 0)

                    if components["op"].strip() == "+":
                        address += offset
                    else:
                        address -= offset

            return address

        return obj.NoneObject("No profile found for module", log=True)

    def get_constant_by_address(self, address):
        self._EnsureInitialized()

        address = obj.Pointer.integer_to_address(address)
        containing_module = self._FindContainingModule(address)
        if containing_module:
            module_name = self._NormalizeModuleName(containing_module)
            module_profile = self.LoadProfileForName(module_name)

            if module_profile:
                constant = module_profile.get_constant_by_address(address)
                if constant:
                    return "%s!%s" % (module_name, constant)

    def get_nearest_constant_by_address(self, address):
        self._EnsureInitialized()

        address = obj.Pointer.integer_to_address(address)
        nearest_offset = 0
        module_name = symbol_name = ""
        profile = None

        # Find the containing module and see if we have a profile for it.
        containing_module = self._FindContainingModule(address)
        if containing_module:
            nearest_offset = containing_module.base
            module_name = self._NormalizeModuleName(containing_module)

            # Try to load the module profile.
            profile = self.LoadProfileForName(module_name)
            if profile:
                offset, name = profile.get_nearest_constant_by_address(
                    address)

                # The profile's constant is closer than the module.
                if address - offset < address - nearest_offset:
                    nearest_offset = offset
                    symbol_name = name

        if symbol_name:
            full_name = "%s!%s" % (module_name, symbol_name)
        else:
            full_name = ""

        return nearest_offset, full_name

    def search_symbol(self, pattern):
        # Currently we only allow searching in the same module.
        self._EnsureInitialized()
        result = []

        components = self._ParseAddress(pattern)
        profile = self.LoadProfileForName(components["module"])

        # Match all symbols.
        symbol_regex = re.compile(components["symbol"].replace("*", ".*"))
        for constant in profile.constants:
            if symbol_regex.match(constant):
                result.append(constant)

        return result
