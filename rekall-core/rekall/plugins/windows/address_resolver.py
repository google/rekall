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
import re

from rekall import addrspace
from rekall import config
from rekall import obj
from rekall import plugin
from rekall import testlib
from rekall import utils
from rekall.plugins.common import address_resolver
from rekall.plugins.windows import common
from rekall.plugins.overlays.windows import pe_vtypes


config.DeclareOption(
    "autodetect_build_local_tracked",
    group="Autodetection Overrides",
    default=["nt", "win32k", "tcpip", "ntdll"],
    type="ArrayStringParser",
    help="When autodetect_build_local is set to 'basic' we fetch these "
    "modules directly from the symbol server.")


# In windows there are two types of mapped PE files - kernel modules and Dlls.

class PEModule(address_resolver.Module):
    """Windows overlays PE files in memory."""

    _profile = None

    def detect_profile_from_session(self):
        """Get the module guid from the session cache.

        This allows the user to override the GUID detection with their own.
        """
        return self.session.GetParameter("%s_profile" % self.name)

    def detect_guid_from_mapped_file(self):
        """Guess the guid for the PE file."""
        # Try to load the file from the physical address space.
        if self.session.physical_address_space.metadata("can_map_files"):
            phys_as = self.session.physical_address_space
            if self.filename:
                image_offset = phys_as.get_mapped_offset(self.filename, 0)
                if image_offset:
                    try:
                        file_as = addrspace.RunBasedAddressSpace(
                            base=phys_as, session=self.session)

                        file_as.add_run(0, image_offset, 2**63)

                        pe_file_as = pe_vtypes.PEFileAddressSpace(
                            base=file_as, session=self.session)

                        pe_helper = pe_vtypes.PE(
                            address_space=pe_file_as,
                            image_base=pe_file_as.image_base,
                            session=self.session)

                        return pe_helper.RSDS.GUID_AGE
                    except IOError:
                        pass

    def detect_guid_pe_header(self):
        # Overlay on the virtual AS.
        pe_helper = pe_vtypes.PE(
            address_space=self.session.GetParameter("default_address_space"),
            image_base=self.start, session=self.session)

        return pe_helper.RSDS.GUID_AGE

    def detect_profile_from_index(self):
        index = self.session.LoadProfile("%s/index" % self.name)
        for profile_name, _ in index.LookupIndex(self.start):
            return profile_name

    def detect_profile_name(self):
        """Try to figure out the profile name for this module.

        We have a number of methods as we need to call these in the most
        appropriate order.
        """
        # Firt check the session - this allows the user to specify the profile
        # directly by storing e.g. win32_profile in the session.
        profile = self.detect_profile_from_session()
        if profile:
            return profile

        # We might have the original file, e.g. in the AFF4 image.
        guid = (self.detect_guid_from_mapped_file() or

                # Maybe we can just read the RSDS value from the mapped pe
                # header.
                self.detect_guid_pe_header())

        if guid:
            return "%s/GUID/%s" % (self.name, guid)

        # Finally try to apply the index if available.
        return self.detect_profile_from_index()

    def build_local_profile(self, profile_name=None, force=False):
        """Fetch and build a local profile from the symbol server."""
        if profile_name is None:
            profile_name = self.detect_profile_name()

        mode = self.session.GetParameter("autodetect_build_local")
        if force or mode == "full" or (
                mode == "basic" and
                self.name in self.session.GetParameter(
                    "autodetect_build_local_tracked")):
            build_local_profile = self.session.plugins.build_local_profile()
            try:
                self.session.logging.debug("Will build local profile %s",
                                           profile_name)
                build_local_profile.fetch_and_parse(profile_name)
                return self.session.LoadProfile(profile_name, use_cache=False)
            except IOError:
                pass

        return obj.NoneObject()

    def build_profile_from_exports(self):
        """Create a dummy profile from PE exports."""
        # Building from export table is slow and might not be needed if the user
        # wants speed.
        if self.session.GetParameter("performance") == "fast":
            return obj.NoneObject()

        self.session.logging.debug("Building profile from PE Exports for %s",
                                   self.name)
        result = obj.Profile.classes["BasicPEProfile"](
            name=self.name,
            session=self.session)

        result.image_base = self.start

        peinfo = self.session.plugins.peinfo(
            image_base=self.start, address_space=self.session.GetParameter(
                "default_address_space"))

        constants = {}
        if "Export" in self.session.GetParameter("name_resolution_strategies"):
            for _, func, name, _ in peinfo.pe_helper.ExportDirectory():
                self.session.report_progress("Merging export table: %s", name)
                func_offset = func.v()
                if not result.get_constant_by_address(func_offset):
                    constants[str(name or "")] = func_offset - self.start

        result.add_constants(constants_are_addresses=True, constants=constants)
        return result

    def reset(self):
        self._profile = None

    @utils.safe_property
    def profile(self):
        if self._profile:
            return self._profile

        return self.load_profile(force=False)

    def load_profile(self, force=True):
        profile_name = self.detect_profile_name()
        if profile_name:
            self._profile = (
                self.session.LoadProfile(profile_name) or
                self.build_local_profile(profile_name, force=force))

        if not self._profile:
            # Profile is not available, should we build it?
            self._profile = self.build_profile_from_exports()

        if not self._profile:
            return obj.NoneObject("Unable to detect GUID")

        self._profile.image_base = self.start
        return self._profile

    @profile.setter
    def profile(self, value):
        """Allow the profile for this module to be overridden."""
        self._profile = value
        if value:
            self._profile.image_base = self.start


class VadModule(PEModule):
    """A Module corresponding to a VAD entry."""
    filename = None

    def __init__(self, vad=None, session=None):
        name = "vad_%#x" % vad.Start
        try:
            # The filename of the _MMVAD
            self.file_obj = vad.ControlArea.FilePointer
            if self.file_obj.v():
                self.filename = self.file_obj.file_name_with_drive()
                name = WindowsAddressResolver.NormalizeModuleName(self.filename)
        except AttributeError:
            # Anonymous module has no name but can be enumerated via
            # address_resolver.modules().
            self.file_obj = self.filename = None

        self.vad = vad
        super(VadModule, self).__init__(
            name=name,
            start=vad.Start,
            end=vad.End,
            session=session)


class KernelModule(PEModule):
    """A Windows kernel module."""
    def __init__(self, ldr_module=None, session=None):
        self.ldr_module = ldr_module
        self.filename = ldr_module.filename or ldr_module.name
        name = WindowsAddressResolver.NormalizeModuleName(self.filename)
        super(KernelModule, self).__init__(
            name=name,
            start=ldr_module.base,
            end=ldr_module.end,
            session=session)


class WindowsAddressResolver(address_resolver.AddressResolverMixin,
                             common.WindowsCommandPlugin):
    """A windows specific address resolver plugin."""

    @classmethod
    def args(cls, parser):
        parser.add_argument(
            "download_profile", default=False,
            help="Try to download the profile for this module from the "
            "symbol server.")

    def __init__(self, download_profile=None, **kwargs):
        super(WindowsAddressResolver, self).__init__(**kwargs)
        self.download_profile = download_profile

    def render(self, _):
        if self.download_profile:
            self.session.address_resolver.GetModuleByName(
                self.download_profile).load_profile(force=True)

    @staticmethod
    def NormalizeModuleName(module_name):
        result = unicode(module_name)
        result = re.split(r"[/\\]", result)[-1]

        # Drop the file extension.
        result = result.split(".")[0]

        # The kernel is treated specially - just like windbg.
        if result in ["ntoskrnl", "ntkrnlpa", "ntkrnlmp"]:
            result = u"nt"

        return result.lower()

    def track_modules(self, *modules):
        """Add module names to the tracked list."""
        already_tracked = self.session.GetParameter(
            'autodetect_build_local_tracked') or []

        needed = set(modules)
        if not needed.issubset(already_tracked):
            needed.update(already_tracked)
            with self.session as session:
                session.SetParameter("autodetect_build_local_tracked", needed)
                for module_name in modules:
                    module_obj = self.GetModuleByName(module_name)
                    if module_obj:
                        # Clear the module's profile. This will force it to
                        # reload a new profile.
                        module_obj.profile = None


    def _EnsureInitialized(self):
        """Initialize the address resolver.

        In windows we populate the virtual address space map from kernel modules
        and VAD mapped files (dlls).
        """
        if self._initialized:
            return

        try:
            # First populate with kernel modules.
            for ldr_entry in self.session.plugins.modules().lsmod():
                self.AddModule(
                    KernelModule(ldr_module=ldr_entry, session=self.session))

            # Windows 10 does not have the kernel in the modules list.
            if not self._modules_by_name.get("nt"):
                start = obj.Pointer.integer_to_address(
                    self.session.GetParameter("kernel_base"))
                pe = pe_vtypes.PE(image_base=start, session=self.session)
                end = start + pe.nt_header.OptionalHeader.SizeOfImage
                self.AddModule(
                    PEModule(
                        session=self.session,
                        name="nt",
                        start=start,
                        end=end,
                        profile=self.session.profile)
                )

            # Now use the vad.
            process_context = self.session.GetParameter("process_context")
            if process_context != None:
                for vad in process_context.RealVadRoot.traverse():
                    self.AddModule(VadModule(vad=vad, session=self.session))

        finally:
            self._initialized = True


class PECommandPlugin(plugin.KernelASMixin, plugin.PhysicalASMixin,
                      plugin.TypedProfileCommand,
                      plugin.ProfileCommand):
    """A command that is active when inspecting a PE file."""
    __abstract = True

    @classmethod
    def is_active(cls, session):
        """We are only active if the profile is windows."""
        return (super(PECommandPlugin, cls).is_active(session) and
                session.profile.name == 'pe')


class PESectionModule(address_resolver.Module):
    """A section in a PE file."""


class PEAddressResolver(address_resolver.AddressResolverMixin,
                        PECommandPlugin):
    """A simple address resolver for PE files."""

    def __init__(self, *args, **kwargs):
        super(PEAddressResolver, self).__init__(*args, **kwargs)
        self.image_base = self.kernel_address_space.image_base
        self.pe_helper = pe_vtypes.PE(
            address_space=self.session.kernel_address_space,
            image_base=self.image_base,
            session=self.session)

    @staticmethod
    def NormalizeModuleName(module_name):
        result = unicode(module_name)
        result = re.split(r"[/\\]", result)[-1]

        # The kernel is treated specially - just like windbg.
        if result in ["ntoskrnl.pdb", "ntkrnlpa.pdb", "ntkrnlmp.pdb"]:
            result = u"nt"

        return result

    def _ParseAddress(self, name):
        capture = super(PEAddressResolver, self)._ParseAddress(name)
        if capture["module"] != "header" and not capture["symbol"]:
            capture["symbol"] = capture["module"]
            capture["module"] = "header"

        return capture

    def _EnsureInitialized(self):
        if self._initialized:
            return

        symbols = {}
        self.pe_profile = None

        # Get a usable profile.
        if "Symbol" in self.session.GetParameter("name_resolution_strategies"):
            # Load the profile for this binary.
            self.pe_profile = self.session.LoadProfile("%s/GUID/%s" % (
                self.NormalizeModuleName(self.pe_helper.RSDS.Filename),
                self.pe_helper.RSDS.GUID_AGE))

        if self.pe_profile == None:
            self.pe_profile = pe_vtypes.BasicPEProfile(session=self.session)

        if "Export" in self.session.GetParameter("name_resolution_strategies"):
            # Extract all exported symbols into the profile's symbol table.
            for _, func, name, _ in self.pe_helper.ExportDirectory():
                func_address = func.v()
                name = utils.SmartUnicode(name)
                symbols[name] = func_address - self.image_base

        self.pe_profile.image_base = self.image_base
        self.pe_profile.add_constants(constants_are_addresses=True,
                                      constants=symbols)

        # A section for the header.
        self.AddModule(
            PESectionModule(start=self.image_base,
                            end=self.image_base+0x1000,
                            name="pe",
                            profile=self.pe_profile,
                            session=self.session))

        # Find the highest address covered in this executable image.
        for _, name, virtual_address, length in self.pe_helper.Sections():
            if length > 0:
                virtual_address += self.image_base
                self.AddModule(
                    PESectionModule(start=virtual_address,
                                    end=virtual_address + length,
                                    name=self.NormalizeModuleName(name),
                                    profile=self.pe_profile,
                                    session=self.session))

        self._initialized = True

    def search_symbol(self, pattern):
        if "!" not in pattern:
            pattern = "pe!" + pattern
        return super(PEAddressResolver, self).search_symbol(pattern)

    def __str__(self):
        self._EnsureInitialized()
        return "<%s: %s@%#x>" % (self.__class__.__name__, self.pe_profile.name,
                                 self.image_base)


class TestWindowsAddressResolver(testlib.DisabledTest):
    PLUGIN = "address_resolver"
