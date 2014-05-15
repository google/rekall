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
import logging

from rekall import config
from rekall import scan
from rekall import kb
from rekall.plugins.darwin import common as darwin_common
from rekall.plugins.linux import common as linux_common
from rekall.plugins.windows import common as win_common


PROFILE_STRINGS = {

    # This maps the name of the XNU kernel to the OSX release as found on:
    # http://www.opensource.apple.com/
    "2422.1.72": "10.9",
    "2050.48.11": "10.8.5",
    "2050.24.15": "10.8.4",
    "2050.22.13": "10.8.3",
    "2050.18.24": "10.8.2",
    "2050.9.2": "10.8.1",
    "2050.7.9": "10.8",
    "1699.32.7": "10.7.5",
    "1699.26.8": "10.7.4",
    "1699.24.23": "10.7.3",
    "1699.24.8": "10.7.2",
    "1699.22.8": "10.7.1",
    "1699.22.73": "10.7",
    "1504.15.3": "10.6.8",
    "1504.9.37": "10.6.7",
    "1504.9.26": "10.6.6",
    "1504.9.17": "10.6.5",
    "1504.7.4": "10.6.4",
    "1504.3.12": "10.6.3",
    "1486.2.11": "10.6.2",
    "1456.1.26": "10.6.1",

    # The signature of an RSDS record.
    "RSDS": "PDB",

    "Linux version ": "Linux",
    }



class ProfileScanner(scan.BaseScanner):
    checks = [("MultiStringFinderCheck", dict(needles=PROFILE_STRINGS))]


config.DeclareOption("--no_autodetect", default=False, action="store_true",
                     help="Should profiles be autodetected.")


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

    # Darwin TEMPLATE from xnu-1699.26.8/libkern/libkern/version.h.template
    DARWIN_TEMPLATE = re.compile(
        r"Darwin Kernel Version .+? "
        r"root:xnu-(\d+\.\d+\.\d+)~\d+/RELEASE_X86_64")

    LINUX_TEMPLATE = re.compile(
        r"Linux version (\d+\.\d+\.\d+-\d+-[^ ]+)")


    def VerifyDarwinProfile(self, profile_name):
        try:
            # Try to load this profile from the repository.
            self.session.profile = self.session.LoadProfile(profile_name)
        except ValueError:
            return

        return self.ApplyFindDTB(darwin_common.DarwinFindDTB,
                                 self.session.profile)

    def VerifyLinuxProfile(self, profile_name):
        try:
            # Try to load this profile from the repository.
            profile = self.session.LoadProfile(profile_name)
        except ValueError:
            return

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
        # Try to load the dtb with this profile. If it works, this is likely
        # correct.
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
            self.session.SetParameter("default_address_space", address_space)
            self.session.SetParameter("dtb", address_space.dtb)

            return profile

    def ScanProfiles(self):
        pe_profile = self.session.LoadProfile("pe")

        address_space = self.session.physical_address_space
        for hit in ProfileScanner(address_space=address_space,
                                  session=self.session).scan():
            rsds = pe_profile.CV_RSDS_HEADER(offset=hit, vm=address_space)
            if (rsds.Signature.is_valid() and
                str(rsds.Filename) in self.KERNEL_NAMES):
                profile = self.VerifyWinProfile(
                    "nt/GUID/%s" % rsds.GUID_AGE)

                if profile:
                    logging.info(
                        "Detected %s with GUID %s", rsds.Filename,
                        rsds.GUID_AGE)

                    return profile

            else:
                guess = address_space.read(hit-100, 300)
                m = self.DARWIN_TEMPLATE.search(guess)
                if m:
                    version = PROFILE_STRINGS.get(m.group(1), "")
                    profile_name = "OSX/%s_AMD" % version
                    profile = self.VerifyDarwinProfile(profile_name)
                    if profile:
                        logging.info(
                            "Detected %s: %s", profile_name, m.group(0))

                        return profile

                m = self.LINUX_TEMPLATE.search(guess)
                if m:
                    # Try to guess the distribution.
                    distribution = "LinuxGeneric"
                    if "Ubuntu" in guess:
                        distribution = "Ubuntu"

                    profile_name = "%s/%s" % (distribution, m.group(1))
                    profile = self.VerifyLinuxProfile(profile_name)
                    if profile:
                        logging.info(
                            "Detected %s: %s", profile_name, m.group(0))

                        return profile


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
