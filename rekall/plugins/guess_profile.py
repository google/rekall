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

from rekall import config

from rekall import kb
from rekall.plugins.windows import common


config.DeclareOption("profile_autodetect", default=True,
                     help="Should profiles be autodetected.")


class ProfileHook(kb.ParameterHook):
    """If the profile is not specified, we guess it."""
    name = "profile"

    # Windows kernel pdb files.
    KERNEL_NAMES = set(["ntoskrnl.pdb", "ntkrnlmp.pdb", "ntkrnlpa.pdb"])


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
        except ValueError:
            return

        # Try to load the dtb with this profile. If it works, this is likely
        # correct.
        win_find_dtb = common.WinFindDTB(
            profile=profile, session=self.session)

        for address_space in win_find_dtb.address_space_hits():
            # Might as well cache the results of this plugin so we dont need to
            # run it twice.
            self.session.kernel_address_space = address_space
            self.session.SetParameter("dtb", address_space.dtb)

            return profile

    def calculate(self):
        """Try to find the correct profile by scanning for PDB files."""
        if not self.session.physical_address_space:
            # Try to load the physical_address_space so we can scan it.
            if not self.session.plugins.load_as().GetPhysicalAddressSpace():
                # No physical address space - nothing to do here.
                return

        # Only do something only if we are allowed to autodetect profiles.
        if self.session.GetParameter("profile_autodetect"):
            logging.info("Searching for windows kernel profile.")

            logging.debug("Autodetecting profile.")
            version_scanner = self.session.plugins.version_scan()
            for rsds, guid in version_scanner.ScanVersions():
                if str(rsds.Filename) in self.KERNEL_NAMES:
                    profile = self.VerifyWinProfile("GUID/%s" % guid)
                    if profile:
                        logging.info(
                            "Detected %s with GUID %s", rsds.Filename, guid)

                        return profile


