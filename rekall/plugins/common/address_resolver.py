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
from rekall import obj


config.DeclareOption(
    "--name_resolution_strategies", default=["Module", "Symbol", "Export"],
    group="Interface", type="ChoiceArray",
    choices=["Module", "Symbol", "Export"])


class AddressResolverMixin(object):
    """The basic building block for constructing an address resolver plugin."""

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
        self.profiles = {}

    def NormalizeModuleName(self, module):
        try:
            module_name = module.name
        except AttributeError:
            module_name = module

        module_name = unicode(module_name)
        module_name = re.split(r"[/\\]", module_name)[-1]

        return module_name.lower()

    def _EnsureInitialized(self):
        """Initialize this address resolver."""

    def _ParseAddress(self, name):
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

            if capture["op"] and not (capture["symbol"] or capture["address"]):
                raise TypeError(
                    "Operator %s must operate on a symbol or address." %
                    capture["op"])

            return capture

        raise TypeError("Unable to parse %r as a symbol name" % name)

    def FindContainingModule(self, address):
        """Finds the name of the module containing the specified address.

        Returns:
          A tuple of start address, end address, module name
        """
        _ = address
        # If we dont know anything about the address just return Nones.
        return None, None, None

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

    def _resolve_module_base_address(self, name):
        module = self.modules_by_name.get(name)
        if module is None:
            return obj.NoneObject("No module %s" % name, log=True)

        return module.base

    def get_address_by_name(self, name):
        self._EnsureInitialized()

        try:
            return int(name)
        except (ValueError, TypeError):
            pass

        if not isinstance(name, basestring):
            raise TypeError("Name should be a string.")

        components = self._ParseAddress(name)
        module_name = components["module"]

        address = components["address"]
        if address:
            address = int(address, 0)

        # User did not specify an address
        if address is None:
            # Found the module we use its base address
            address = self._resolve_module_base_address(module_name)
            if address == None:
                return obj.NoneObject(
                    "No module %s found" % module_name, log=True)

        # Search for a symbol in the module.
        if components["symbol"]:
            # Get the profile for this module.
            module_profile = self.LoadProfileForName(module_name)
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
                module_profile = self.LoadProfileForName(containing_module.name)

            if not module_profile:
                module_profile = self.session.profile

            address = module_profile.Pointer(address).v()

        return address

    def format_address(self, address, max_distance=0x1000):
        """Format the address as a symbol name.

        This means to try and find the containing module, the symbol within the
        module or possibly an offset from a known symbol. e.g.

        nt!PspCidTable
        nt!PspCidTable + 0x10
        nt + 0x234

        Returns an empty string if the address is not in a containing module, or
        if the nearest known symbol is farther than max_distance away.
        """
        _ = address
        _ = max_distance
        return ""

    def get_nearest_constant_by_address(self, address):
        """Searches for a known symbol at an address lower than this.

        Returns a tuple (nearest_offset, full_name of symbol).
        """
        _ = address
        return (0xFFFFFFFFFF, "")

    def search_symbol(self, pattern):
        """Searches symbols for the pattern.

        pattern may contain wild cards (*). Note that currently a module name is
        required. Example pattern:

        nt!Ps*
        """
