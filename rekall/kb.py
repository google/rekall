# This module provides for a central knowledge base which plugins can use to
# collect information.

import bisect
import logging
import re

from rekall import obj
from rekall import registry

class KernelModule(object):
    def __init__(self, session):
        self.session = session
        self.name = "nt"
        self.base = self.session.GetParameter("kernel_base")


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
        r"(?P<deref>[*])?"              # Pointer dereference.

        r"((?P<address>0x[0-9A-Fa-f]+)|" # Alternative - Either an address, or,

        r"(?P<module>[A-Za-z_0-9\.]+)"  # Module name - can include extension
                                        # (.exe, .sys)

        r"!?"                           # ! separates module name from symbol
                                        # name.

        r"(?P<symbol>[^ +-]+)?"         # Symbol name.
        r")"                            # End alternative.

        r"(?P<op> *[+-] *)?"            # Possible arithmetic operator.
        r"(?P<offset>[0-9a-fA-Fx]+)?")  # Possible hex offset.

    def __init__(self, session):
        self.session = session
        self.vad = None
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
            if not capture.get("address"):
                module = capture.get("module")
                if not module:
                    raise TypeError("Module name not specified.")

                capture["module"] = self._NormalizeModuleName(module)

            if capture["op"] and not (capture["symbol"] or
                                      capture["address"] or
                                      capture["module"]):
                raise TypeError("Operator %s must have an operand." %
                                capture["op"])

            if capture["op"] and not (capture["symbol"] or capture["address"]):
                raise TypeError(
                    "Operator %s must operate on a symbol or address." %
                    capture["op"])

            return capture

        raise TypeError("Unable to parse %r as a symbol name" % name)

    def _FindContainingModule(self, address):
        if self.modules:
            return self.modules.find_module(address)

    def _FindProcessVad(self, address):
        task = self.session.GetParameter("process_context")
        if task and self.vad:
            return self.vad.find_file_in_task(address, task)

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

                self.profiles["nt"] = self.session.profile
                self.modules_by_name["nt"] = KernelModule(self.session)

            except AttributeError:
                self.modules = None

        if self.vad is None and hasattr(self.session.plugins, "vad"):
            # Hold on to the vad plugin for resolving process address
            # spaces. The vad plugin maintains its own per-process cache so we
            # do not need to reset it here.
            self.vad = self.session.plugins.vad()

    def _LoadProfile(self, module_name, profile):
        self._EnsureInitialized()
        try:
            module_name = self._NormalizeModuleName(module_name)
            # Try to get the profile directly from the local cache.
            if module_name in self.profiles:
                return self.profiles[module_name]

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

    def LoadProfileForDll(self, module_base, module_name):
        self._EnsureInitialized()

        if module_name in self.profiles:
            return self.profiles[module_name]

        # Create a dummy profile.
        result = obj.Profile.classes["BasicPEProfile"](
            name=module_name,
            session=self.session)

        result.image_base = module_base

        peinfo = self.session.plugins.peinfo(
            image_base=module_base, address_space=self.session.GetParameter(
                "default_address_space"))

        constants = {}
        for _, func, name, _ in peinfo.pe_helper.ExportDirectory():
            self.session.report_progress("Merging export table: %s", name)
            func_offset = func.v()
            if not result.get_constant_by_address(func_offset):
                constants[str(name or "")] = func_offset - module_base

        result.add_constants(constants_are_addresses=True, **constants)

        self.profiles[module_name] = result

        return result

    def LoadProfileForModule(self, module):
        self._EnsureInitialized()
        result = None
        module_base = module.base

        module_name = self._NormalizeModuleName(module)
        if module_name in self.profiles:
            return self.profiles[module_name]

        guid = module.RSDS.GUID_AGE
        if guid:
            result = self._LoadProfile(
                module_name, "%s/GUID/%s" % (module_name, guid))

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
                constants[str(name or "")] = func_offset - module_base

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

        # Try to detect the profile from the module object.
        module = self.modules_by_name.get(module_name)
        if module:
            return self.LoadProfileForModule(module)

    def get_address_by_name(self, name):
        self._EnsureInitialized()

        try:
            return int(name)
        except ValueError:
            pass

        if not isinstance(name, basestring):
            raise TypeError("Name should be a string.")

        components = self._ParseAddress(name)
        address = components["address"]
        if address:
            address = int(address, 0)

        # User did not specify an address
        if address is None:
            module = self.modules_by_name.get(components["module"])
            if module is None:
                return obj.NoneObject("No module %s" % name, log=True)

            # Found the module we use its base address
            address = module.base

        # Search for a symbol in the module.
        if components["symbol"]:
            # Get the profile for this module.
            module_profile = self.LoadProfileForModule(module)
            if module_profile:
                address = module_profile.get_constant(
                    components["symbol"], True)
            else:
                return obj.NoneObject(
                    "No profile found for module", log=True)

        # Support basic offset operations (+/-).
        if components["op"]:
            # Parse the offset as hex or decimal.
            offset = int(components["offset"], 0)
            op = components["op"].strip()
            if op == "+":
                address += offset
            elif op == "-":
                address -= offset
            else:
                raise TypeError("Operator '%s' not supported" % op)

        # If the symbol was a dereference, we need to read the address from
        # this offset.
        if components.get("deref"):
            module_profile = None
            containing_module = self._FindContainingModule(address)
            if containing_module:
                module_profile = self.LoadProfileForModule(containing_module)

            if not module_profile:
                module_profile = self.session.profile

            address = module_profile.Pointer(address).v()

        return address

    def _format_address_from_profile(self, profile, address):
        nearest_offset, name = profile.get_nearest_constant_by_address(
            address)

        if name:
            difference = address - nearest_offset
            if difference == 0:
                return "%s!%s" % (profile.name, name)
            else:
                return "%s!%s+%#x" % (profile.name, name, difference)
        else:
            return "%s!+%#x" % (profile.name, address - profile.image_base)

    def format_address(self, address, max_distance=0x1000):
        address = obj.Pointer.integer_to_address(address)

        # Try to locate the symbol below it.
        offset, name = self.get_nearest_constant_by_address(address)
        difference = address - offset

        if name:
            if difference == 0:
                return name

            # Ensure address falls within the current module.
            containing_module = self._FindContainingModule(address)
            if (containing_module and address < containing_module.end and
                0 < difference < max_distance):
                return "%s + %#x" % (
                    name, address - offset)

            else:
                hit = self._FindProcessVad(address)
                if hit:
                    start, end, name = hit
                    if start < address < end:
                        profile = self.LoadProfileForDll(start, name)
                        return self._format_address_from_profile(
                            profile, address)

        return ""

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
            else:
                return module_name

        # Check the process context for process addresses.
        hit = self._FindProcessVad(address)
        if hit:
            start, _, name = hit
            return "%s + %#x" % (name, address-start)

    def get_nearest_constant_by_address(self, address):
        self._EnsureInitialized()

        address = obj.Pointer.integer_to_address(address)
        nearest_offset = 0
        full_name = module_name = symbol_name = ""
        profile = None

        # Find the containing module and see if we have a profile for it.
        containing_module = self._FindContainingModule(address)
        if containing_module:
            nearest_offset = containing_module.base
            full_name = module_name = self._NormalizeModuleName(
                containing_module)

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
            vad_desc = self._FindProcessVad(address)
            if vad_desc:
                start, _, full_name = vad_desc
                nearest_offset = start
                profile = self.LoadProfileForDll(start, full_name)

                if profile:
                    offset, name = profile.get_nearest_constant_by_address(
                        address)

                    # The profile's constant is closer than the module.
                    if address - offset < address - nearest_offset:
                        nearest_offset = offset
                        symbol_name = name

                if symbol_name:
                    full_name = "%s!%s" % (module_name, symbol_name)

        return nearest_offset, full_name

    def search_symbol(self, pattern):
        # Currently we only allow searching in the same module.
        self._EnsureInitialized()
        result = []

        components = self._ParseAddress(pattern)
        module_name = components["module"]
        profile = self.LoadProfileForName(module_name)

        # Match all symbols.
        symbol_regex = re.compile(components["symbol"].replace("*", ".*"))
        for constant in profile.constants:
            if symbol_regex.match(constant):
                result.append("%s!%s" % (module_name, constant))

        return result
