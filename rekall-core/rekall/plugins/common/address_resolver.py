# Rekall Memory Forensics
# Copyright 2014 Google Inc. All Rights Reserved.
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

"""The module implements the base class for address resolution."""

__author__ = "Michael Cohen <scudette@gmail.com>"

import re

from rekall import config
from rekall import plugin
from rekall import obj
from rekall import utils


config.DeclareOption(
    "--name_resolution_strategies", default=["Module", "Symbol", "Export"],
    group="Interface", type="ChoiceArray",
    choices=["Module", "Symbol", "Export"])


class Module(object):
    """A range in the virtual address space which maps an executable.

    Each binary in the address space has its own profile, which knows about
    symbols within it. This simple class is just a container to facilitate
    access to the profile that represents this module.

    Within Rekall, each module has a name. Rekall uses a simple syntax to refer
    to an address in the address space by name (see below).
    """
    def __init__(self, name=None, start=None, end=None, profile=None,
                 session=None):
        self.name = name
        self.start = int(start)
        self.end = int(end)
        self.profile = profile
        self.session = session

    def __str__(self):
        return "%s: %s" % (self.__class__.__name__, self.name)


class AddressResolverMixin(object):

    """The basic building block for constructing an address resolver plugin.

    An address resolver maintains a collection of Modules and abstracts access
    to specific symbol names within the modules.

    Rekall uses a symbolic notation to refer to specific addresses within the
    address space. The address resolver is responsible for parsing this notation
    and resolving it to an actual address.

    Rules of symbol syntax
    ======================

    The address space is divided into "modules". A module has a name, a start
    address and an end address. Modules can also contain a profile which knows
    about symbols related to that module.

    1. Module reference: The start address of a module can be refered to by its
       name. e.g:  "nt", "ntdll", "tcpip".

    2. If a module contains a valid profile, the profile may also know about
       symbols within the module. We can refer to these
       symbols. e.g. "nt!MmGetIoSessionState"

    3. If an exact symbol is not found, it can be referred to with an offset
       from another symbol name. e.g. "nt!MmGetIoSessionState+5FE" (Note
       integers are given in hex).

    4. If the symbol is preceeded with a "*" - it means that the symbol is a
       pointer. The address will be read as a pointer and the symbol name will
       resolve to the address of the pointer's target.

    """

    __args = [
        dict(name="symbol", type="ArrayString", default=[],
             help="List of symbols to lookup"),
    ]

    table_header = [
        dict(name="Symbol", width=20),
        dict(name="Offset", width=20, style="address"),
    ]

    # The name of the plugin.
    name = "address_resolver"

    # The format of a symbol name. Used by get_address_by_name().
    ADDRESS_NAME_REGEX = re.compile(
        r"(?P<deref>[*])?"              # Pointer dereference.

        r"((?P<address>0x[0-9A-Fa-f]+)|" # Alternative - Either an address, or,

        r"(?P<module>[A-Za-z_0-9\.\\]+)" # Module name - can include extension
                                         # (.exe, .sys)

        r"!?"                           # ! separates module name from symbol
                                        # name.

        r"(?P<symbol>[^ +-]+)?"         # Symbol name.
        r")"                            # End alternative.

        r"(?P<op> *[+-] *)?"            # Possible arithmetic operator.
        r"(?P<offset>[0-9a-fA-Fx]+)?")  # Possible hex offset.

    def __init__(self, **kwargs):
        super(AddressResolverMixin, self).__init__(**kwargs)
        self.reset()

    def reset(self):
        # A ranged collection of Module() objects.
        self._address_ranges = utils.RangedCollection()

        # A lookup between module names and the Module object itself.
        self._modules_by_name = {}

        self._initialized = False

    def NormalizeModuleName(self, module_name):
        if module_name is not None:
            module_name = unicode(module_name)
            module_name = re.split(r"[/\\]", module_name)[-1]

            return module_name.lower()

    def _EnsureInitialized(self):
        """Initialize this address resolver."""

    def AddModule(self, module):
        self._address_ranges.insert(module.start, module.end, module)
        if module.name:
            self._modules_by_name[module.name] = module

    def _ParseAddress(self, name):
        """Parses the symbol from Rekall symbolic notation.

        Raises:
          TypeError if the expression has a syntax error.

        Returns:
          a dict containing the different components of the expression.
        """
        m = self.ADDRESS_NAME_REGEX.match(name)
        if m:
            capture = m.groupdict()
            if not capture.get("address"):
                module = capture.get("module")
                if not module:
                    raise TypeError("Module name not specified.")

                capture["module"] = self.NormalizeModuleName(module)

            if capture["op"] and not (capture["symbol"] or
                                      capture["address"] or
                                      capture["module"]):
                raise TypeError("Operator %s must have an operand." %
                                capture["op"])

            if capture["op"] and not (capture["symbol"] or capture["address"] or
                                      capture["module"]):
                raise TypeError(
                    "Operator %s must operate on a symbol or address." %
                    capture["op"])

            return capture

        raise TypeError("Unable to parse %r as a symbol name" % name)

    def modules(self):
        self._EnsureInitialized()
        for _, _, module in self._address_ranges:
            yield module

    def GetContainingModule(self, address):
        """Finds the module containing the specified address.

        Returns:
          A Module() instance.
        """
        self._EnsureInitialized()
        address = obj.Pointer.integer_to_address(address)

        _, _, module = self._address_ranges.get_containing_range(address)
        return module

    def GetModuleByName(self, name):
        self._EnsureInitialized()
        return self._modules_by_name.get(self.NormalizeModuleName(name))

    def GetAllModules(self):
        self._EnsureInitialized()
        return self._modules_by_name.values()

    def get_constant_object(self, name, target=None, **kwargs):
        """Instantiate the named constant with these args.

        This method is the main entry point for instantiating constants. It is
        preferred than calling the profile's method of the same name directly
        since it will be responsible with loading the right profile.
        """
        self._EnsureInitialized()

        # Parse the name
        components = self._ParseAddress(name)
        if not components["symbol"]:
            raise ValueError("No symbol name specified.")

        module = self._modules_by_name.get(components["module"])
        if module is not None:
            # Just delegate to the module's profile.
            if module.profile:
                return module.profile.get_constant_object(
                    components["symbol"], target=target, **kwargs)

        return obj.NoneObject("Profile for name %s unknown." % name, log=True)

    def get_address_by_name(self, name):
        """Convert the symbol annotated by name to an address."""
        self._EnsureInitialized()

        try:
            return int(name)
        except (ValueError, TypeError):
            pass

        if not isinstance(name, basestring):
            raise TypeError("Name should be a string.")

        module = None
        components = self._ParseAddress(name)
        module_name = self.NormalizeModuleName(components["module"])
        address = components["address"]
        if address is not None:
            address = int(address, 0)
        # User did not specify an address
        else:
            module = self._modules_by_name.get(module_name)
            if not module:
                return obj.NoneObject(
                    "No module %s found" % module_name, log=True)

            # Found the module we use its base address
            address = module.start

        # Search for a symbol in the module.
        symbol = components["symbol"]
        if symbol:
            # Get the profile for this module.
            if module.profile:
                address = module.profile.get_constant(symbol, is_address=True)

            else:
                return obj.NoneObject("No profile found for module", log=True)

        # Support basic offset operations (+/-).
        op = components["op"]
        if op:
            op = op.strip()
            # Parse the offset as hex or decimal.
            offset = int(components["offset"], 0)
            if op == "+":
                address += offset
            elif op == "-":
                address -= offset
            else:
                raise TypeError("Operator '%s' not supported" % op)

        # If the symbol was a dereference, we need to read the address from
        # this offset.
        if components.get("deref"):
            try:
                address = module.profile.Pointer(address).v()
            except AttributeError:
                address = self.session.profile.Pointer(address).v()

        return address

    def format_address(self, address, max_distance=0x1000000):
        """Format the address as a symbol name.

        This means to try and find the containing module, the symbol within the
        module or possibly an offset from a known symbol. e.g.

        nt!PspCidTable
        nt!PspCidTable + 0x10
        nt + 0x234

        Returns a list of symbol names for the address. The list is empty if the
        address is not in a containing module if the nearest known symbol is
        farther than max_distance away.
        """
        self._EnsureInitialized()

        _, symbols = self.get_nearest_constant_by_address(
            address, max_distance=max_distance)

        return sorted(symbols)

    def get_nearest_constant_by_address(self, address, max_distance=0x1000000):
        """Searches for a known symbol at an address lower than this.

        Returns a tuple (nearest_offset, list of symbol names).
        """
        self._EnsureInitialized()

        address = obj.Pointer.integer_to_address(address)
        symbols = []
        module = self.GetContainingModule(address)
        if not module or not module.name:
            return (-1, [])

        if module.profile != None:
            offset, symbols = module.profile.get_nearest_constant_by_address(
                address)

        # Symbols not found at all, use module name.
        if not symbols:
            if address - module.start > max_distance:
                return (-1, [])

            if address == module.start:
                return (module.start, [module.name])

            return (module.start, [
                "%s+%#x" % (module.name, address - module.start)])

        if address - offset > max_distance:
            return (-1, [])

        # Exact symbols found.
        if offset == address:
            return (offset, ["%s!%s" % (module.name, x) for x in symbols])

        # Approximate symbol found, check if the profile knows its type.
        for x in symbols:
            if x in module.profile.constant_types:
                type_name = self._format_type(module, x, address)
                if type_name is not None:
                    return (offset, ["%s!%s" % (module.name, type_name)])

        return (offset, ["%s!%s+%#x" % (module.name, x, address - offset)
                         for x in symbols])

    def _format_type(self, module, symbol, offset):
        """Use the type information to format the address within the struct."""
        result = symbol
        member_obj = module.profile.get_constant_object(symbol)

        while offset > member_obj.obj_offset:
            if isinstance(member_obj, obj.Struct):
                members = [
                    getattr(member_obj, x, None) for x in member_obj.members]
                member_collection = utils.SortedCollection(
                    (x.obj_offset, x) for x in members)

                member_offset, member_below = (
                    member_collection.get_value_smaller_than(offset))

                # No member below this offset?
                if member_offset is None:
                    result += "+%s" % (offset - member_obj.obj_offset)
                    break

                result += ".%s" % member_below.obj_name
                member_obj = member_below

            elif isinstance(member_obj, obj.Array):
                # Next lowest index is a whole number of items.
                item = member_obj[0]
                next_lowest_index = (
                    offset - member_obj.obj_offset) / item.obj_size
                result += "[%s]" % next_lowest_index

                member_obj = member_obj[next_lowest_index]

            else:
                result += "+%s" % (offset - member_obj.obj_offset)
                break

        return result

    def search_symbol(self, pattern):
        """Searches symbols for the pattern.

        pattern may contain wild cards (*). Note that currently a module name is
        required. Example pattern:

        nt!Ps*
        """
        self._EnsureInitialized()
        result = []

        components = self._ParseAddress(pattern)
        module_name = self.NormalizeModuleName(components["module"])
        if module_name == None:
            raise RuntimeError(
                "Module name must be specified for symbol search.")

        module = self._modules_by_name.get(module_name)
        if module:
            # Match all symbols.
            symbol_regex = re.compile(components["symbol"].replace("*", ".*"))
            if module.profile:
                for constant in module.profile.constants:
                    if symbol_regex.match(constant):
                        result.append("%s!%s" % (module_name, constant))

        return result

    def collect(self):
        for symbol in self.plugin_args.symbol:
            yield symbol, self.get_address_by_name(symbol)
