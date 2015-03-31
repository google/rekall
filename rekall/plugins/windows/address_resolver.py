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

"""The module implements the windows specific address resolution plugin."""

__author__ = "Michael Cohen <scudette@gmail.com>"
import logging
import re

from rekall import obj
from rekall import plugin
from rekall import testlib
from rekall import utils
from rekall.plugins.common import address_resolver
from rekall.plugins.windows import common
from rekall.plugins.overlays.windows import pe_vtypes
from rekall.plugins.overlays.windows import windows


class KernelModule(object):
    def __init__(self, session):
        self.session = session
        self.name = "nt"
        self.base = self.session.GetParameter("kernel_base")


class WindowsAddressResolver(address_resolver.AddressResolverMixin,
                             common.WindowsCommandPlugin):
    """A windows specific address resolver plugin."""

    def __init__(self, **kwargs):
        super(WindowsAddressResolver, self).__init__(**kwargs)
        self.vad = None
        self.modules = None
        self.modules_by_name = {}

    def _EnsureInitialized(self):
        if self.modules is None:
            try:
                self.modules = self.session.plugins.modules()
                for module in self.modules.lsmod():
                    module_name = self.NormalizeModuleName(module)
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

    def NormalizeModuleName(self, module):
        try:
            module_name = module.name
        except AttributeError:
            module_name = module

        module_name = unicode(module_name)
        module_name = re.split(r"[/\\]", module_name)[-1]
        result = module_name.split(".")[0]
        if result == "ntoskrnl":
            result = "nt"

        return result.lower()

    def FindProcessVad(self, address, cache_only=False):
        """Find the VAD corresponding with the address.

        If cache_only is specified we can only use cached values. If the cache
        is empty we fail the request. This is needed to avoid recursion loops in
        the address space.
        """
        if cache_only and self.vad is None:
            return

        self._EnsureInitialized()
        task = self.session.GetParameter("process_context")
        if task:
            return self.vad.find_file_in_task(address, task)

    def GetVADs(self):
        self._EnsureInitialized()
        task = self.session.GetParameter("process_context")
        if task:
            return self.vad.GetVadsForProcess(task)

        return []

    def _FindContainingModule(self, address):
        """Find the kernel module which contains the address."""
        if self.modules:
            return self.modules.find_module(address)

    def FindContainingModule(self, address):
        """Finds the name of the module containing the specified address.

        In windows we search in the following order:
        1) Search all kernel modules to see if we can find the address.

        2) If we are in process context - search all vads to see if the address
           is found.

        Returns:
          A tuple of start address, end address, name
          """
        self._EnsureInitialized()

        # The address may be in kernel space or user space.
        containing_module = self._FindContainingModule(address)

        if containing_module:
            name = self.NormalizeModuleName(containing_module.name)
            return containing_module.base, containing_module.size, name

        # Maybe the address is in userspace.
        containing_VAD = self.FindProcessVad(address)

        # We find the vad and it
        if containing_VAD:
            start, end, name, _ = containing_VAD
            return start, end, self.NormalizeModuleName(name)

        # If we dont know anything about the address just return Nones.
        return None, None, None

    def _LoadProfile(self, module_name, profile):
        self._EnsureInitialized()
        try:
            module_name = self.NormalizeModuleName(module_name)
            # Try to get the profile directly from the local cache.
            if module_name in self.profiles:
                return self.profiles[module_name]

            module = self.modules_by_name[module_name]

            module_profile = (self.session.LoadProfile(profile) or
                              self._build_local_profile(module_name, profile))

            module_profile.image_base = module.base

            # Merge in the kernel profile into this profile.
            module_profile.merge(self.session.profile)

            self.profiles[module_name] = module_profile

            return module_profile

        except (ValueError, KeyError):
            # Cache the fact that we did not find this profile.
            self.profiles[module_name] = None
            logging.debug("Unable to resolve symbols in module %s",
                          module_name)

            return obj.NoneObject()

    def LoadProfileForDll(self, module_base, module_name):
        self._EnsureInitialized()

        if module_name in self.profiles:
            return self.profiles[module_name]

        # Try to determine the DLL's GUID.
        pe_helper = pe_vtypes.PE(
            address_space=self.session.GetParameter("default_address_space"),
            image_base=module_base,
            session=self.session)

        # TODO: Apply profile index to detect the profile.
        guid_age = pe_helper.RSDS.GUID_AGE
        if guid_age:
            profile_name = "%s/GUID/%s" % (module_name, guid_age)
            profile = (self.session.LoadProfile(profile_name) or
                       self._build_local_profile(module_name, profile_name))

            if profile:
                profile.name = module_name
                profile.image_base = module_base

                self.profiles[module_name] = profile
                return profile

        result = self._build_profile_from_exports(module_base, module_name)
        self.profiles[module_name] = result
        return result

    # Build these modules locally even if autodetect_build_local is "basic".
    TRACKED_MODULES = set(["tcpip", "win32k", "ntdll"])

    def _build_local_profile(self, module_name, profile_name):
        """Fetch a build a local profile from the symbol server."""
        mode = self.session.GetParameter("autodetect_build_local")
        if mode == "full" or (mode == "basic" and
                              module_name in self.TRACKED_MODULES):
            build_local_profile = self.session.plugins.build_local_profile()
            try:
                logging.debug("Will build local profile %s", profile_name)
                build_local_profile.fetch_and_parse(profile_name)
                return self.session.LoadProfile(profile_name, use_cache=False)
            except IOError:
                pass

        return obj.NoneObject()

    def _build_profile_from_exports(self, module_base, module_name):
        """Create a dummy profile from PE exports."""
        result = obj.Profile.classes["BasicPEProfile"](
            name=module_name,
            session=self.session)

        result.image_base = module_base

        peinfo = self.session.plugins.peinfo(
            image_base=module_base, address_space=self.session.GetParameter(
                "default_address_space"))

        constants = {}
        if "Export" in self.session.GetParameter("name_resolution_strategies"):
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

        module_name = self.NormalizeModuleName(module)
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
        if "Export" in self.session.GetParameter("name_resolution_strategies"):
            for _, func, name, _ in peinfo.pe_helper.ExportDirectory():
                self.session.report_progress("Merging export table: %s", name)
                func_offset = func.v()
                if not result.get_constant_by_address(func_offset):
                    constants[str(name or "")] = func_offset - module_base

            result.add_constants(constants_are_addresses=True, **constants)

        self.profiles[module_name] = result

        return result

    def LoadProfileForModuleNameByName(self, module_name, profile_name):
        """Loads a profile for a module by its full profile name.

        This is needed if we can not determine the GUID for some reason from the
        memory image. The user is able to provide the GUID (E.g. from disk
        image).
        """
        self._EnsureInitialized()

        profile = self.session.LoadProfile(profile_name, use_cache=False)
        module_base = self._resolve_module_base_address(module_name)
        if module_base:
            profile.image_base = module_base
            self.profiles[module_name] = profile

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

        module_base = self._resolve_module_base_address(module_name)
        if module_base:
            return self.LoadProfileForDll(module_base, module_name)

        return obj.NoneObject()

    def _resolve_module_base_address(self, name):
        module = self.modules_by_name.get(name)
        if module is not None:
            return module.base

        # Try to match the module name to a VAD region (e.g. a DLL).
        task = self.session.GetParameter("process_context")
        if task:
            name = name.lower()
            for start, _, filename, _ in self.vad.GetVadsForProcess(task):
                if re.search("%s.(dll|exe)" % name, filename.lower()):
                    return start

    def _format_address_from_profile(self, profile, address,
                                     max_distance=0x1000):
        nearest_offset, name = profile.get_nearest_constant_by_address(
            address)

        if name:
            difference = address - nearest_offset
            if difference == 0:
                return "%s!%s" % (profile.name, name)
            elif 0 < difference < max_distance:
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
                hit = self.FindProcessVad(address)
                if hit:
                    start, end, name, _ = hit
                    if (start < address < end and
                            0 < address - start < max_distance):
                        module_name = self.NormalizeModuleName(name)

                        profile = self.LoadProfileForDll(start, module_name)
                        return self._format_address_from_profile(
                            profile, address, max_distance=max_distance)

        return ""

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
            full_name = module_name = self.NormalizeModuleName(
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
            vad_desc = self.FindProcessVad(address)
            if vad_desc:
                start, _, full_name, _ = vad_desc
                module_name = self.NormalizeModuleName(full_name)
                nearest_offset = start
                profile = self.LoadProfileForDll(start, module_name)

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


class PECommandPlugin(plugin.KernelASMixin, plugin.PhysicalASMixin,
                      plugin.ProfileCommand):
    """A command that is active when inspecting a PE file."""
    __abstract = True

    @classmethod
    def is_active(cls, session):
        """We are only active if the profile is windows."""
        return (super(PECommandPlugin, cls).is_active(session) and
                session.profile.name == 'pe')


class PESectionModule(object):
    def __init__(self, name, start, length):
        self.name = utils.SmartStr(name)
        self.base = start
        self.length = length
        self.end = self.base + self.length


class PEAddressResolver(address_resolver.AddressResolverMixin,
                        PECommandPlugin):
    """A simple address resolver for PE files."""

    def __init__(self, **kwargs):
        super(PEAddressResolver, self).__init__(**kwargs)
        self.address_map = utils.SortedCollection(key=lambda x: x[0])
        self.section_map = utils.SortedCollection(key=lambda x: x[0])
        self.image_base = self.kernel_address_space.image_base
        self.pe_helper = pe_vtypes.PE(
            address_space=self.session.kernel_address_space,
            image_base=self.image_base,
            session=self.session)

        # Delay initialization until we need it.
        self._initialized = False

    def NormalizeModuleName(self, module):
        try:
            module_name = module.name
        except AttributeError:
            module_name = module

        module_name = utils.SmartUnicode(module_name)
        module_name = re.split(r"[/\\]", module_name)[-1]
        result = module_name.split(".")[0]

        return result.lower()

    def LoadProfileForName(self, _):
        self._EnsureInitialized()

        return self.pe_profile

    def _FindContainingModule(self, address):
        self._EnsureInitialized()

        address = obj.Pointer.integer_to_address(address)
        try:
            _, module = self.section_map.find_le(address)
            if address < module.end:
                return module

        except ValueError:
            pass

        return obj.NoneObject("Unknown module")

    def _EnsureInitialized(self):
        if self._initialized:
            return

        self.modules_by_name = {}
        symbols = {}

        # Insert a psuedo module for each section
        module_end = self.image_base

        # If the executable has a pdb file, we use that as its .text module
        # name.
        if self.pe_helper.RSDS.Filename:
            module_name = self.NormalizeModuleName(self.pe_helper.RSDS.Filename)
        else:
            module_name = ""

        # Find the highest address covered in this executable image.
        for _, name, virtual_address, length in self.pe_helper.Sections():
            if self.image_base + virtual_address + length > module_end:
                module_end = virtual_address + length + self.image_base

        # Make a single module which covers the entire length of the executable
        # in virtual memory.
        module = PESectionModule(
            module_name, self.image_base, module_end - self.image_base)
        self.modules_by_name[module.name] = module
        self.section_map.insert((module.base, module))

        if "Export" in self.session.GetParameter("name_resolution_strategies"):
            # Extract all exported symbols into the profile's symbol table.
            for _, func, name, _ in self.pe_helper.ExportDirectory():
                func_address = func.v()
                try:
                    symbols[utils.SmartUnicode(name)] = func_address
                except ValueError:
                    continue

        if "Symbol" in self.session.GetParameter("name_resolution_strategies"):
            # Load the profile for this binary.
            self.pe_profile = self.session.LoadProfile("%s/GUID/%s" % (
                utils.SmartUnicode(self.pe_helper.RSDS.Filename).split(".")[0],
                self.pe_helper.RSDS.GUID_AGE))
        else:
            self.pe_profile = windows.BasicPEProfile(session=self.session)

        self.pe_profile.image_base = self.image_base

        self.pe_profile.add_constants(constants_are_addresses=True,
                                      relative_to_image_base=False,
                                      **symbols)

        self._initialized = True

    def format_address(self, address, max_distance=0x1000):
        self._EnsureInitialized()

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

    def get_nearest_constant_by_address(self, address):
        self._EnsureInitialized()

        if self.pe_profile == None:
            return 0, ""

        offset, name = self.pe_profile.get_nearest_constant_by_address(address)

        # Find the containing section.
        containing_module = self._FindContainingModule(address)
        if containing_module:
            if name:
                name = "%s!%s" % (containing_module.name, name)
            else:
                name = containing_module.name

        return offset, name

    def search_symbol(self, pattern):
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

    def __str__(self):
        self._EnsureInitialized()
        return "<%s: %s@%#x>" % (self.__class__.__name__, self.pe_profile.name,
                                 self.image_base)


class TestWindowsAddressResolver(testlib.DisabledTest):
    PLUGIN = "address_resolver"
