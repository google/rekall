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

"""This script rebuilds all the profiles in the repository.

We assume the repository contains a directory "files/" which contains all the pe
files of ntoskrnl.exe. We then iterate over them, download their pdb files, and
parse these - finally creating a Rekall repository.

The final directory contains paths under:

ntoskrnl.exe/$ARCH/$VERSION/$GUID
GUID/$GUID    <- This is a symlink to the full path.


For example:
ntoskrnl.exe/AMD64/6.1.7601.17514/3844DBB920174967BE7AA4A2C20430FA2
GUID/3844DBB920174967BE7AA4A2C20430FA2

"""

__author__ = "Michael Cohen <scudette@google.com>"

import json
import os
import sys
import multiprocessing

from rekall import interactive
session = interactive.ImportEnvironment(verbose="debug")

NUMBER_OF_CORES = multiprocessing.cpu_count()


def EnsurePathExists(path):
    try:
        os.makedirs(path)
    except OSError:
        pass


def BuildProfile(pdb_path, filename, profile_path, target_path, symlink_path,
                 metadata):
    session.RunPlugin(
        "parse_pdb",
        filename=os.path.join(pdb_path, filename),
        output=profile_path,
        metadata=metadata)

    with open(symlink_path, "wb") as fd:
        json.dump({
                "$METADATA": dict(
                    Type="Symlink",
                    Target=target_path,
                    )
                }, fd)


def BuildAllProfiles(executable_path, rebuild=False):
    executable_path = os.path.abspath(executable_path)
    pool = multiprocessing.Pool(NUMBER_OF_CORES)

    for filename in os.listdir(os.path.join(executable_path, "files")):
        path = os.path.join(executable_path, "files", filename)
        try:
            peinfo = session.plugins.peinfo(filename=path)
        except IOError:
            continue

        version_info = dict(peinfo.pe_helper.VersionInformation())

        # The version string e.g. 5.2.3790.4354
        version = version_info["ProductVersion"]
        major, minor, revision = version.split(".", 2)

        # The guid + age as needed by the MS symbol server.
        guid = peinfo.pe_helper.RSDS.GUID_AGE
        filename = str(peinfo.pe_helper.RSDS.Filename)
        arch = str(peinfo.pe_helper.nt_header.FileHeader.Machine).split("_")[-1]

        # Fetch the pdb from the MS symbol server.
        output_path = os.path.join(executable_path, arch, version)
        EnsurePathExists(output_path)

        implementation = os.path.basename(executable_path).split(
            ".")[0].capitalize()

        profile_path = os.path.join(output_path, guid)
        pdb_path = os.path.join(output_path, "%s.pdb" % guid)
        pdb_filename = os.path.join(pdb_path, filename)
        EnsurePathExists(pdb_path)

        # Dont bother downloading the pdb file if we already have it.
        if not os.access(pdb_filename, os.R_OK):
            session.RunPlugin(
                "fetch_pdb",
                filename=filename, guid=guid,
                dump_dir=pdb_path)


        # Do not export the profile if we already have it.
        if rebuild or not os.access(profile_path, os.R_OK):
            metadata = dict(
                ProfileClass=implementation,
                major=major,
                minor=minor,
                arch=arch,
                revision=revision)

            print "Exporting profile %s" % profile_path
            # Make the symlink to it.
            EnsurePathExists("GUID")
            symlink_path = os.path.join("GUID", guid)

            # Target path is relative to the root of the repository.
            target_path = profile_path[
                len(os.path.dirname(executable_path))+1:]

            pool.apply_async(
                BuildProfile,
                (pdb_path, filename, profile_path, target_path,
                 symlink_path, metadata))


    # Wait here until all the pool workers are done.
    pool.close()
    pool.join()


if __name__ == "__main__":
    BuildAllProfiles(sys.argv[1])
