# Rekall Memory Forensics
# Copyright (C) 2014 Michael Cohen
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

"""This module guesses the current profile using various heuristics."""

__author__ = "Michael Cohen <scudette@gmail.com>"

# pylint: disable=protected-access
import re
import os

from rekall import addrspace
from rekall import cache
from rekall import config
from rekall import kb
from rekall import obj
from rekall import registry
from rekall import scan
from rekall import utils

from rekall.plugins.addrspaces import amd64
from rekall.plugins.addrspaces import intel
from rekall.plugins.darwin import common as darwin_common
from rekall.plugins.linux import common as linux_common
from rekall.plugins.windows import common as win_common
from rekall.plugins.overlays.windows import pe_vtypes


class DetectionMethod(object):
    """A baseclass to implement autodetection methods."""

    __metaclass__ = registry.MetaclassRegistry
    name = None

    order = 100

    def __init__(self, session=None):
        self.session = session

    def Offsets(self):
        """Return a list of offsets we care about."""
        return []

    def Keywords(self):
        """Returns a list of keywords which will be searched.

        Each time the keyword is matched, this instance will be called to
        attempt detection.
        """
        return []

    find_dtb_impl = None

    def VerifyProfile(self, profile_name):
        """Check that the profile name is valid."""
        profile = self.session.LoadProfile(profile_name)

        if profile != None:
            return self._ApplyFindDTB(self.find_dtb_impl, profile)

    def _ApplyFindDTB(self, find_dtb_cls, profile):
        """Verify profile by trying to use it to load the dtb.

        If this succeeds the profile is likely correct.
        """
        self.session.profile = profile

        find_dtb_plugin = find_dtb_cls(session=self.session)

        # Allow the dtb to be specified on the command line.
        dtb = self.session.GetParameter("dtb")
        if dtb:
            # Verify the DTB to make sure it is correct.
            if not find_dtb_plugin.VerifyHit(dtb):
                return

            address_space = find_dtb_plugin.CreateAS(dtb)
            self.session.SetCache(
                "default_address_space", address_space, volatile=False)

            return profile

        for address_space in find_dtb_plugin.address_space_hits():
            # Might as well cache the results of this plugin so we dont need to
            # run it twice.
            self.session.kernel_address_space = address_space

            # Start off with a default address space of the kernel.
            with self.session as session:
                session.SetCache("default_address_space", address_space,
                                 volatile=False)
                session.SetCache("dtb", address_space.dtb, volatile=False)

            return profile

    def DetectFromHit(self, hit, file_offset, address_space):
        """Gets called for each hit.

        If a profile matches, return it, otherwise None.
        """


# By default use all detection modules.
config.DeclareOption("autodetect", group="Autodetection Overrides",
                     type="ChoiceArray", required=True,
                     choices=utils.JITIterator(DetectionMethod),
                     default=utils.JITIterator(DetectionMethod),
                     help="Autodetection method.")

config.DeclareOption("autodetect_threshold", default=1.0,
                     group="Autodetection Overrides",
                     help="Worst acceptable match for profile autodetection." +
                     " (Default 1.0)",
                     type="Float")

config.DeclareOption("autodetect_build_local", default="basic",
                     group="Autodetection Overrides",
                     choices=["full", "basic", "none"],
                     help="Attempts to fetch and build profile locally.",
                     type="Choices")

config.DeclareOption("autodetect_scan_length", default=2**64,
                     group="Autodetection Overrides",
                     help="How much of physical memory to scan before failing",
                     type="IntParser")


class WindowsIndexDetector(DetectionMethod):
    """Apply the windows index to detect the profile."""

    find_dtb_impl = win_common.WinFindDTB

    name = "nt_index"

    def __init__(self, **kwargs):
        super(WindowsIndexDetector, self).__init__(**kwargs)

        self.eprocess_index = self.session.LoadProfile("nt/eprocess_index")
        self.nt_index = self.session.LoadProfile("nt/index")

    def Keywords(self):
        """We trigger when we see some common windows processes.

        Since all windows processes also map the kernel we can detect it.
        """
        return ["cmd.exe\x00\x00", "System\x00\x00", "csrss.exe\x00\x00",
                "svchost.exe\x00\x00", "lsass.exe\x00\x00",
                "winlogon.exe\x00\x00"]

    def Offsets(self):
        return [0]

    def VerifyAMD64DTB(self, test_as):
        """Verify this address space.

        Checks that the _KUSER_SHARED_DATA makes sense. This structure is always
        at a known offset since it must be shared with user space apps.
        """
        kuser_shared = self.eprocess_index._KUSER_SHARED_DATA(
            offset=0xFFFFF78000000000, vm=test_as)

        # Must be a valid version of windows.
        if (kuser_shared.NtMajorVersion in [5, 6, 10] and
                kuser_shared.NtMinorVersion in [0, 1, 2, 3]):
            return True

    def VerifyI386DTB(self, test_as):
        """Verify this address space.

        Checks that the _KUSER_SHARED_DATA makes sense. This structure is always
        at a known offset since it must be shared with user space apps.
        """
        kuser_shared = self.eprocess_index._KUSER_SHARED_DATA(
            offset=0xffdf0000, vm=test_as)

        # Must be a valid version of windows.
        if (kuser_shared.NtMajorVersion in [5, 6, 10] and
                kuser_shared.NtMinorVersion in [0, 1, 2, 3]):
            return True

    def DetectWindowsDTB(self, filename_offset, address_space):
        """Checks the possible filename hit for a valid DTB address."""
        for dtb_rel_offset, arch in self.eprocess_index.filename_to_dtb:
            # We only apply indexes to 64 bit images.
            if arch == "AMD64":
                possible_dtb = self.eprocess_index.Object(
                    "unsigned long", offset=filename_offset - dtb_rel_offset,
                    vm=address_space).v()

                # Discard impossible DTB values immediately. On 64 bit
                # architectures, the DTB must be page aligned.
                if not possible_dtb or possible_dtb & 0xFFF:
                    continue

                test_as = amd64.AMD64PagedMemory(
                    session=self.session, base=address_space, dtb=possible_dtb)
                if self.VerifyAMD64DTB(test_as):
                    yield test_as

            elif arch == "I386":
                possible_dtb = self.eprocess_index.Object(
                    "unsigned long", offset=filename_offset - dtb_rel_offset,
                    vm=address_space).v()

                # Discard impossible DTB values immediately. On 32 bit
                # architectures, the DTB must be aligned to 0x20 (with PAE).
                if not possible_dtb or possible_dtb & 0x1F:
                    continue

                # Only support PAE - we dont really see non PAE images any more.
                test_as = intel.IA32PagedMemoryPae(
                    session=self.session, base=address_space, dtb=possible_dtb)
                if self.VerifyI386DTB(test_as):
                    yield test_as

    def _match_profile_for_kernel_base(self, kernel_base, test_as):
        threshold = self.session.GetParameter("autodetect_threshold")
        for profile, match in self.nt_index.LookupIndex(
                kernel_base, address_space=test_as):

            if match < threshold:
                break

            profile_obj = self.session.LoadProfile(profile)
            if profile_obj:
                return profile_obj

    def DetectFromHit(self, hit, filename_offset, address_space):
        # Make use of already known dtb and kernel_base parameters - this speeds
        # up live analysis significantly since we do not need to search for
        # anything then.
        if filename_offset == 0:
            if (self.session.HasParameter("dtb") and
                    self.session.HasParameter("kernel_base")):
                test_as = amd64.AMD64PagedMemory(
                    session=self.session, base=address_space,
                    dtb=self.session.GetParameter("dtb"))

                if self.VerifyAMD64DTB(test_as):
                    return self._match_profile_for_kernel_base(
                        self.session.GetParameter("kernel_base"),
                        test_as)

            return

        # Get potential kernel address spaces.
        for test_as in self.DetectWindowsDTB(filename_offset, address_space):
            # Try to find the kernel base. This can be improved in future by
            # taking more than a single search point.
            scanner = scan.MultiStringScanner(
                address_space=test_as, needles=[
                    "This program cannot be run in DOS mode",
                ])

            if self.session.HasParameter("kernel_base"):
                kernel_base = self.session.GetParameter("kernel_base")
                return self._match_profile_for_kernel_base(
                    kernel_base, test_as)

            for offset, _ in scanner.scan(
                    offset=0xF80000000000, maxlen=0x10000000000):
                kernel_base = offset & 0xFFFFFFFFFFFFFF000
                profile_obj = self._match_profile_for_kernel_base(
                    kernel_base, test_as)

                if profile_obj:
                    return profile_obj


class PEImageFileDetector(DetectionMethod):

    name = "pe"
    order = 50

    def __init__(self, **kwargs):
        super(PEImageFileDetector, self).__init__(**kwargs)
        self.pe_profile = self.session.LoadProfile("pe")

    def Offsets(self):
        # We only care about the first offset in the file.
        return [0]

    def DetectFromHit(self, hit, _, address_space):
        # If the file is a PE file, we simply return the PE address space.
        if self.pe_profile._IMAGE_DOS_HEADER(vm=address_space).NTHeader:
            pe_as = pe_vtypes.PEFileAddressSpace(
                base=address_space, profile=self.pe_profile)

            self.session.kernel_address_space = pe_as
            self.session.SetCache("default_image_base", pe_as.image_base)

            machine_type = pe_as.nt_header.FileHeader.Machine
            if machine_type == "IMAGE_FILE_MACHINE_AMD64":
                self.pe_profile.set_metadata("arch", "AMD64")
            else:
                self.pe_profile.set_metadata("arch", "I386")

            return self.pe_profile


class WindowsRSDSDetector(DetectionMethod):
    """A detection method based on the scanning for RSDS signatures."""

    name = "rsds"
    order = 90

    # Windows kernel pdb files.
    KERNEL_NAMES = win_common.KERNEL_NAMES

    find_dtb_impl = win_common.WinFindDTB

    def __init__(self, **kwargs):
        super(WindowsRSDSDetector, self).__init__(**kwargs)
        self.pe_profile = self.session.LoadProfile("pe")

    def Keywords(self):
        return ["RSDS"]

    def Offsets(self):
        return [0]

    def VerifyProfile(self, profile_name):
        profile = self.session.LoadProfile(profile_name)

        # If the user allows it we can just try to fetch and build the profile
        # locally.
        if profile == None and self.session.GetParameter(
                "autodetect_build_local") in ("full", "basic"):
            build_local_profile = self.session.plugins.build_local_profile()
            try:
                self.session.logging.debug(
                    "Will build local profile %s", profile_name)
                build_local_profile.fetch_and_parse(profile_name)
                profile = self.session.LoadProfile(
                    profile_name, use_cache=False)

            except IOError:
                pass

        if profile != None:
            return self._ApplyFindDTB(self.find_dtb_impl, profile)

    def DetectFromHit(self, hit, offset, address_space):
        # Make use of already known dtb and kernel_base parameters - this speeds
        # up live analysis significantly since we do not need to search for
        # anything then.
        if (offset == 0 and self.session.HasParameter("dtb") and
                self.session.HasParameter("kernel_base")):
            test_as = amd64.AMD64PagedMemory(
                session=self.session, base=address_space,
                dtb=self.session.GetParameter("dtb"))

            pe_helper = pe_vtypes.PE(
                session=self.session,
                address_space=test_as,
                image_base=self.session.GetParameter("kernel_base"))

            return self._test_rsds(pe_helper.RSDS)

        # Try Windows by GUID:
        rsds = self.pe_profile.CV_RSDS_HEADER(offset=offset, vm=address_space)
        return self._test_rsds(rsds)

    def _test_rsds(self, rsds):
        if (rsds.Signature.is_valid() and
                str(rsds.Filename) in self.KERNEL_NAMES):
            profile = self.VerifyProfile("nt/GUID/%s" % rsds.GUID_AGE)

            if profile:
                self.session.logging.info(
                    "Detected %s with GUID %s", rsds.Filename,
                    rsds.GUID_AGE)

                return profile


class WindowsKernelImageDetector(WindowsRSDSDetector):
    name = "windows_kernel_file"
    order = 50

    def Offsets(self):
        return [0]

    KERNEL_PATHS = [r"C:\Windows\SysNative\ntoskrnl.exe",
                    r"C:\Windows\System32\ntoskrnl.exe"]

    def DetectFromHit(self, hit, _, address_space):
        for potential_path in self.KERNEL_PATHS:
            # Try to make the kernel image into the address_space.
            image_offset = address_space.get_mapped_offset(potential_path, 0)

            if image_offset is not None:
                file_as = addrspace.RunBasedAddressSpace(
                    base=address_space, session=self.session)
                file_as.add_run(0, image_offset, 2**63)

                pe_file_as = pe_vtypes.PEFileAddressSpace(
                    base=file_as, session=self.session)

                pe_helper = pe_vtypes.PE(
                    session=self.session,
                    address_space=pe_file_as,
                    image_base=pe_file_as.image_base)

                rsds = pe_helper.RSDS
                self.session.logging.info(
                    "Found RSDS in kernel image: %s (%s)",
                    rsds.GUID_AGE, rsds.Filename)
                result = self._test_rsds(rsds)
                if result:
                    return result


class LinuxIndexDetector(DetectionMethod):
    """A kernel detector that uses live symbols to do exact matching.

    LinuxIndexDetector uses kallsyms (or any other source of live symbols) to
    match a kernel exactly by finding known-unique symbols.
    """

    name = "linux_index"


    find_dtb_impl = linux_common.LinuxFindDTB

    def __init__(self, **kwargs):
        super(LinuxIndexDetector, self).__init__(**kwargs)
        self.index = self.session.LoadProfile("Linux/index")

    def Offsets(self):
        return [0]

    def DetectFromHit(self, hit, offset, address_space):
        if offset != 0:
            return

        self.session.logging.debug(
            "LinuxIndexDetector:DetectFromHit(%x) = %s", offset, hit)

        kaslr_reader = linux_common.KAllSyms(self.session)

        # We create a dictionary of symbol:offset skipping symbols from
        # exported modules.
        symbol_dict = {}
        for offset, symbol, _, module in kaslr_reader.ObtainSymbols():
            # Ignore symbols in modules we only care about the kernel.
            if not module:
                symbol_dict[symbol] = offset

        if not symbol_dict:
            return

        matching_profiles = self.index.LookupProfile(symbol_dict)
        if len(matching_profiles) > 1:
            self.session.logging.info(
                "LinuxIndexDetector found %d matching profiles: %s",
                len(matching_profiles),
                ', '.join([p[0] for p in matching_profiles]))
            return
        elif len(matching_profiles) == 1:
            profile_id = matching_profiles[0][0]
            self.session.logging.info(
                "LinuxIndexDetector found profile %s with %d/%d matches.",
                profile_id,
                matching_profiles[0][1],
                len(self.index.traits[profile_id]))

            profile = self.session.LoadProfile(profile_id)
            if profile:
                # At this point we also know the kernel slide.
                kallsyms_proc_banner = symbol_dict["linux_proc_banner"]
                profile_proc_banner = profile.get_constant("linux_proc_banner",
                                                           is_address=False)
                kernel_slide = kallsyms_proc_banner - profile_proc_banner
                self.session.logging.info("Found slide 0x%x", kernel_slide)
                self.session.SetCache("kernel_slide", kernel_slide)

                verified_profile = self.VerifyProfile(profile)
                if verified_profile:
                    return verified_profile
                else:
                    self.session.SetCache("kernel_slide", None)
        # If we were unable to find a matching Linux profile, we limit the scan
        # length to prevent Rekall from spinning for a long time.
        self.session.logging.warn("LinuxIndexDetector found no matches.")
        self._LimitScanLength()

    def _LimitScanLength(self):
        self.session.SetParameter("autodetect_scan_length", 1024*1024*1024)


class LinuxBannerDetector(DetectionMethod):
    """Detect a linux kernel from its banner text."""

    name = "linux"

    LINUX_TEMPLATE = re.compile(
        r"Linux version (\d+\.\d+\.\d+[^ ]+)")

    find_dtb_impl = linux_common.LinuxFindDTB

    def Keywords(self):
        # The Linux kernels we care about contain this.
        return ["Linux version "]

    def DetectFromHit(self, hit, offset, address_space):
        guess = address_space.read(offset - 100, 300)
        m = self.LINUX_TEMPLATE.search(guess)
        if m:
            # Try to guess the distribution.
            distribution = "LinuxGeneric"
            if "Ubuntu" in guess:
                distribution = "Ubuntu"

            if "Debian" in guess:
                distribution = "Debian"

            profile_name = "%s/%s" % (distribution, m.group(1))
            profile = self.session.LoadProfile(profile_name)
            if profile:
                self.session.logging.info(
                    "Detected %s: %s", profile_name, m.group(0))
            else:
                return

            # At this point we should know the kernel slide.
            profile_proc_banner = profile.get_constant("linux_banner",
                                                       is_address=False)
            expected_proc_banner = profile.phys_addr(profile_proc_banner)
            kernel_slide = offset - expected_proc_banner
            self.session.logging.info("Found slide 0x%x", kernel_slide)
            self.session.SetCache("kernel_slide", kernel_slide)
            verified_profile = self.VerifyProfile(profile)
            if not verified_profile:
                self.session.SetCache("kernel_slide", None)

            return verified_profile


class DarwinIndexDetector(DetectionMethod):
    """Detect the Darwin version using the index.

    To work around KASLR, we have an index of known symbols' offsets relative to
    the Catfish string, along with the data we expect to find at those
    offsets. Profile similarity is the percentage of these symbols that match as
    expected.

    Ideally, we'd like a 100% match, but in case we don't have the exact
    profile, we'll make do with anything higher than 0% that can resolve the
    DTB.
    """
    name = "osx"

    find_dtb_impl = darwin_common.DarwinFindDTB

    def __init__(self, **kwargs):
        super(DarwinIndexDetector, self).__init__(**kwargs)
        self.index = self.session.LoadProfile("OSX/index")

    def Keywords(self):
        # Found in every OS X image. See documentation for DarwinFindKASLR for
        # details.
        return ["Catfish \x00\x00"]

    def DetectFromHit(self, hit, offset, address_space):
        for profile_name, match in self.index.LookupIndex(
                image_base=offset,
                address_space=self.session.physical_address_space):
            profile = self.VerifyProfile(profile_name)
            if profile:
                self.session.logging.info(
                    "New best match: %s (%.0f%% match)",
                    profile_name, match * 100)

                self.session.SetCache("catfish_offset", offset, volatile=False)

                return profile


class KernelASHook(kb.ParameterHook):
    """A ParameterHook for default_address_space.

    This will only be called if default_address_space is not set. We load the
    kernel address space, or load it if needed.
    """
    name = "default_address_space"

    volatile = False

    def calculate(self):
        if self.session.kernel_address_space:
            return self.session.kernel_address_space

        try:
            return self.session.plugins.load_as().GetVirtualAddressSpace()
        except Exception:
            return obj.NoneObject("Address space not found")


class ProfileHook(kb.ParameterHook):
    """If the profile is not specified, we guess it."""
    name = "profile_obj"

    volatile = False

    def ScanProfiles(self):
        try:
            self.session.SetCache("execution_phase", "ProfileAutodetect")
            return self._ScanProfiles()
        finally:
            self.session.SetCache("execution_phase", None)

    def _ScanProfiles(self):
        address_space = self.session.physical_address_space
        best_profile = None
        best_match = 0

        methods = []
        needles = []
        needle_lookup = {}

        method_names = self.session.GetParameter("autodetect")

        self.session.logging.debug(
            "Will detect profile using these Detectors: %s" % ",".join(
                method_names))

        if not method_names:
            raise RuntimeError("No autodetection methods specified. "
                               "Use the --autodetect parameter.")

        for method_name in method_names:
            for method in DetectionMethod.classes_by_name[method_name]:
                methods.append(method(session=self.session))

        methods.sort(key=lambda x: x.order)
        for method in methods:
            for keyword in method.Keywords():
                needles.append(keyword)
                needle_lookup.setdefault(keyword, []).append(method)

            for offset in method.Offsets():
                self.session.logging.debug("Trying method %s, offset %d",
                                           method.name, offset)
                profile = method.DetectFromHit(None, offset, address_space)
                if profile:
                    self.session.logging.info(
                        "Detection method %s yielded profile %s",
                        method.name, profile)
                    return profile

        # 10 GB by default.
        autodetect_scan_length = self.session.GetParameter(
            "autodetect_scan_length", 10*1024*1024*1024)

        # Build and configure the scanner.
        scanner = scan.MultiStringScanner(
            profile=obj.NoneObject(),
            address_space=address_space, needles=needles,
            session=self.session)
        scanner.progress_message = "Autodetecting profile: %(offset)#08x"
        for offset, hit in scanner.scan(maxlen=autodetect_scan_length):
            self.session.render_progress(
                "guess_profile: autodetection hit @ %x - %s", offset, hit)

            for method in needle_lookup[hit]:
                profile = method.DetectFromHit(hit, offset, address_space)
                if profile:
                    self.session.logging.debug(
                        "Detection method %s worked at offset %#x",
                        method.name, offset)
                    return profile

            if best_match == 1.0:
                # If we have an exact match we can stop scanning.
                break

        threshold = self.session.GetParameter("autodetect_threshold")
        if best_match == 0:
            self.session.logging.error(
                "No profiles match this image. Try specifying manually.")

            return obj.NoneObject("No profile detected")

        elif best_match < threshold:
            self.session.logging.error(
                "Best match for profile is %s with %.0f%%, which is too low " +
                "for given threshold of %.0f%%. Try lowering " +
                "--autodetect-threshold.",
                best_profile.name,
                best_match * 100,
                threshold * 100)

            return obj.NoneObject("No profile detected")

        else:
            self.session.logging.info(
                "Profile %s matched with %.0f%% confidence.",
                best_profile.name,
                best_match * 100)

            return best_profile

    def calculate(self):
        """Try to find the correct profile by scanning for PDB files."""
        # Clear the profile for the duration of the scan.
        self.session.profile = obj.NoneObject("Unset")
        if not self.session.physical_address_space:
            # Try to load the physical_address_space so we can scan it.
            if not self.session.plugins.load_as().GetPhysicalAddressSpace():
                # If a filename was specified this should have worked, unless we
                # could not open it.
                filename = self.session.GetParameter("filename")
                if filename:
                    raise RuntimeError(
                        "Unable to instantiate physical_address_space from "
                        "filename %s." % filename)

                # No physical address space - nothing to do here.
                return obj.NoneObject("No Physical Address Space.")

        # If the global cache is persistent we try to detect this image by
        # fingerprint if we have seen it before.
        if self.session.cache.__class__ == cache.FileCache:
            name = self.session.cache.DetectImage(
                self.session.physical_address_space)
            if name:
                self.session.logging.info(
                    "Detected fingerprinted image %s", name)

        # Allow the user to specify the profile to use on the command line.
        profile_name = self.session.GetParameter("profile")
        if profile_name:
            profile_obj = self.session.LoadProfile(profile_name)
            if profile_obj != None:
                return profile_obj

        # Is the profile object already cached?
        profile_obj = self.session.cache.Get("profile_obj")
        if not profile_obj:
            profile_obj = self.ScanProfiles()
            if not profile_obj:
                raise RuntimeError(
                    "Unable to find a valid profile for this image. "
                    "Try using -v for more details.")

        # Update the session profile.
        self.session.profile = profile_obj

        if (self.session.GetParameter("cache") == "file" and
                self.session.HasParameter("image_fingerprint")):
            self.session.cache.SetFingerprint(
                self.session.GetParameter("image_fingerprint"))

        return profile_obj
