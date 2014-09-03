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
import logging
import re

from rekall import config
from rekall import kb
from rekall import scan
from rekall.plugins.darwin import common as darwin_common
from rekall.plugins.linux import common as linux_common
from rekall.plugins.windows import common as win_common
from rekall.plugins.overlays.windows import pe_vtypes

OSX_NEEDLE = "Catfish \x00\x00"

PROFILE_STRINGS = [
    # Anything that looks like a RSDS record signature.
    "RSDS",

    # Found in every OS X image. See documentation for DarwinFindKASLR for
    # details.
    OSX_NEEDLE,

    # The Linux kernels we care about contain this.
    "Linux version ",
]


class ProfileScanner(scan.BaseScanner):
    checks = [("MultiStringFinderCheck", dict(needles=PROFILE_STRINGS))]


config.DeclareOption("--no_autodetect", default=False, action="store_true",
                     help="Should profiles be autodetected.")

config.DeclareOption("--autodetect_threshold", default=1.0, action="store",
                     help="Worst acceptable match for profile autodetection." +
                     " (Default 1.0)",
                     type=float)

class KernelASHook(kb.ParameterHook):
    """A ParameterHook for default_address_space.

    This will only be called if default_address_space is not set. We load the
    kernel address space, or load it if needed.
    """
    name = "default_address_space"

    def calculate(self):
        if not self.session.profile:
            self.session.GetParameter("profile")

        if self.session.kernel_address_space:
            return self.session.kernel_address_space

        return self.session.plugins.load_as().GetVirtualAddressSpace()


class ProfileHook(kb.ParameterHook):
    """If the profile is not specified, we guess it."""
    name = "profile"

    # Windows kernel pdb files.
    KERNEL_NAMES = win_common.KERNEL_NAMES

    LINUX_TEMPLATE = re.compile(
        r"Linux version (\d+\.\d+\.\d+[^ ]+)")


    def VerifyDarwinProfile(self, profile_name):
        try:
            # Try to load this profile from the repository.
            self.session.profile = self.session.LoadProfile(profile_name)
        except ValueError:
            return

        return self.ApplyFindDTB(darwin_common.DarwinFindDTB,
                                 self.session.profile)

    def VerifyLinuxProfile(self, profile_name):
        profile = self.session.LoadProfile(profile_name)
        if profile != None:
            return self.ApplyFindDTB(linux_common.LinuxFindDTB, profile)

    def VerifyWinProfile(self, profile_name):
        """Check that this profile works with this image.

        Currently we construct a valid DTB with this profile. This might have
        trouble distinguishing profiles which are fairly close (e.g. Win7
        versions).
        """
        logging.debug("Verifying profile %s", profile_name)

        try:
            # Try to load this profile from the repository.
            profile = self.session.LoadProfile(profile_name)
        except ValueError as e:
            logging.info("Error loading profile: %s" % e)
            return

        return self.ApplyFindDTB(win_common.WinFindDTB, profile)

    def ApplyFindDTB(self, find_dtb_cls, profile):
        """Verify profile by trying to use it to load the dtb.

        If this succeeds the profile is likely correct.
        """
        self.session.profile = profile

        find_dtb_plugin = find_dtb_cls(session=self.session)

        # Allow the dtb to be specified on the command line.
        dtb = self.session.GetParameter("dtb")
        if dtb:
            address_space = find_dtb_plugin.CreateAS(dtb)
            self.session.SetParameter("default_address_space", address_space)
            return profile

        for address_space in find_dtb_plugin.address_space_hits():
            # Might as well cache the results of this plugin so we dont need to
            # run it twice.
            self.session.kernel_address_space = address_space

            # Start off with a default address space of the kernel.
            with self.session as session:
                session.SetParameter("default_address_space", address_space)
                session.SetParameter("dtb", address_space.dtb)

            return profile

    def ScanProfiles(self):
        pe_profile = self.session.LoadProfile("pe")
        address_space = self.session.physical_address_space
        best_profile = None
        best_match = 0

        # If the file is a PE file, we simply return the PE address space.
        if pe_profile._IMAGE_DOS_HEADER(vm=address_space).NTHeader:
            pe_as = pe_vtypes.PEFileAddressSpace(
                base=address_space, profile=pe_profile)

            self.session.kernel_address_space = pe_as
            self.session.SetParameter("default_image_base", pe_as.image_base)

            machine_type = pe_as.nt_header.FileHeader.Machine
            if machine_type == "IMAGE_FILE_MACHINE_AMD64":
                pe_profile.set_metadata("arch", "ADM64")

            return pe_profile

        for hit in ProfileScanner(address_space=address_space,
                                  session=self.session).scan():

            # Try Windows by GUID:
            rsds = pe_profile.CV_RSDS_HEADER(offset=hit, vm=address_space)
            if (rsds.Signature.is_valid() and
                str(rsds.Filename) in self.KERNEL_NAMES):
                profile = self.VerifyWinProfile(
                    "nt/GUID/%s" % rsds.GUID_AGE)

                if profile:
                    logging.info(
                        "Detected %s with GUID %s", rsds.Filename,
                        rsds.GUID_AGE)

                    best_profile = profile
                    best_match = 1

            # Try OS X by profile similarity:
            elif address_space.read(hit, len(OSX_NEEDLE)) == OSX_NEEDLE:
                # To work around KASLR, we have an index of known symbols'
                # offsets relative to the Catfish string, along with the data we
                # expect to find at those offsets. Profile similarity is the
                # percentage of these symbols that match as expected.
                #
                # Ideally, we'd like a 100% match, but in case we don't have the
                # exact profile, we'll make do with anything higher than 0% that
                # can resolve the DTB.
                logging.debug("Hit for Darwin at 0x%x", hit)
                index = self.session.LoadProfile("OSX/index")
                for profile_name, match in index.LookupIndex(
                    image_base=hit,
                    address_space=self.session.physical_address_space):
                    profile = self.VerifyDarwinProfile(profile_name)
                    if profile:
                        if match > best_match:
                            logging.info(
                                "New best match: %s (%.0f%% match)",
                                profile_name, match * 100)
                            best_profile, best_match = profile, match
                            self.session.SetParameter("catfish_offset", hit)

                            if match == 1.0:
                                break

            # Try Linux by version string:
            else:
                guess = address_space.read(hit-100, 300)

                m = self.LINUX_TEMPLATE.search(guess)
                if m:
                    # Try to guess the distribution.
                    distribution = "LinuxGeneric"
                    if "Ubuntu" in guess:
                        distribution = "Ubuntu"

                    if "Debian" in guess:
                        distribution = "Debian"

                    profile_name = "%s/%s" % (distribution, m.group(1))
                    profile = self.VerifyLinuxProfile(profile_name)
                    if profile:
                        logging.info(
                            "Detected %s: %s", profile_name, m.group(0))

                        best_profile = profile
                        best_match = 1

            if best_match == 1.0:
                # If we have an exact match we can stop scanning.
                break

        threshold = self.session.GetParameter("autodetect_threshold")
        if best_match == 0:
            logging.error(
                "No profiles match this image. Try specifying manually.")

        elif best_match < threshold:
            logging.error(
                "Best match for profile is %s with %.0f%%, which is too low " +
                "for given threshold of %.0f%%. Try lowering " +
                "--autodetect-threshold.",
                best_profile.name,
                best_match * 100,
                threshold * 100)

        else:
            logging.info(
                "Profile %s matched with %.0f%% confidence.",
                best_profile.name,
                best_match * 100)

            return best_profile

    def calculate(self):
        """Try to find the correct profile by scanning for PDB files."""
        if not self.session.physical_address_space:
            # Try to load the physical_address_space so we can scan it.
            if not self.session.plugins.load_as().GetPhysicalAddressSpace():
                # No physical address space - nothing to do here.
                return

        # Only do something only if we are allowed to autodetect profiles.
        if not self.session.GetParameter("no_autodetect"):
            return self.ScanProfiles()
