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

"""The module implements the linux specific address resolution plugin."""

__author__ = "Michael Cohen <scudette@gmail.com>"
import re

from rekall import obj
from rekall import utils
from rekall.plugins.common import address_resolver
from rekall.plugins.linux import common


class KernelModule(object):
    """A Fake object which makes the kernel look like a module.

    This removes the need to treat kernel addresses any different from module
    addresses, and allows them to be resolved by this module.
    """

    def __init__(self, session):
        self.session = session

        # Check if the address appears in the kernel binary.
        self.module_core = self.base = obj.Pointer.integer_to_address(
            self.session.profile.get_constant("_text"))

        self.end = self.session.profile.get_constant("_etext")
        self.core_size = self.size = self.end - self.base
        self.name = "linux"


class LinuxAddressResolver(address_resolver.AddressResolverMixin,
                           common.LinuxPlugin):
    """A Linux specific address resolver plugin."""

    def __init__(self, **kwargs):
        super(LinuxAddressResolver, self).__init__(**kwargs)
        self.address_map = utils.SortedCollection(key=lambda x: x[0])

        # Delay initialization until we need it.
        self._initialized = False

    def _EnsureInitialized(self):
        if self._initialized:
            return

        # Insert a psuedo module for the kernel
        modules = [KernelModule(self.session)]
        modules.extend(self.session.plugins.lsmod().get_module_list())
        self.modules_by_name = {}
        for module in modules:
            self.address_map.insert((module.base, module))
            self.modules_by_name[module.name] = module

        self._initialized = True

    def _FindContainingModule(self, address):
        """Find the kernel module which contains the address."""
        self._EnsureInitialized()

        address = obj.Pointer.integer_to_address(address)
        try:
            _, module = self.address_map.find_le(address)
            if address < module.end:
                return module

        except ValueError:
            pass

        return obj.NoneObject("Unknown module")

    def FindContainingModule(self, address):
        """Finds the name of the module containing the specified address.

        In linux we currect only support kernel modules.

        Returns:
          A tuple of start address, end address, module name
          """
        self._EnsureInitialized()

        # The address may be in kernel space or user space. Currently we only
        # resolve addresses in kernel space.
        containing_module = self._FindContainingModule(address)

        return (containing_module.base, containing_module.size,
                containing_module.name)

    def LoadProfileForName(self, module):
        # Currently, on Linux, we only support kernel symbols.
        # TODO: Develop an ELF export parser for exported kernel module symbols.
        if module == "linux":
            return self.session.profile

        return obj.NoneObject("Module profiles are not supported yet.")

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
            full_name = module_name = containing_module.name

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

        return nearest_offset, full_name

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

        return ""

    def search_symbol(self, pattern):
        # Currently we only allow searching in the same module.
        self._EnsureInitialized()
        result = []

        components = self._ParseAddress(pattern)
        module_name = components["module"]
        if module_name == None:
            raise RuntimeError(
                "Module name must be specified for symbol search.")

        profile = self.LoadProfileForName(module_name)

        # Match all symbols.
        symbol_regex = re.compile(components["symbol"].replace("*", ".*"))
        for constant in profile.constants:
            if symbol_regex.match(constant):
                result.append("%s!%s" % (module_name, constant))

        return result
