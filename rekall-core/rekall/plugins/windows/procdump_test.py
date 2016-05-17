# Rekall Memory Forensics
#
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Authors:
# Michael Cohen <scudette@gmail.com>
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

"""Tests for the procexecdump plugins."""
from rekall import testlib


class TestProcdump(testlib.HashChecker):
    """Test the Procdump module."""

    PARAMETERS = dict(
        commandline="procdump %(pids)s --dump_dir %(tempdir)s",
        pid=2536
        )


class TestModDump(testlib.HashChecker):
    PARAMETERS = dict(
        commandline="moddump --regex %(driver)s --dump_dir %(tempdir)s",
        driver="ntoskrnl.exe"
        )


class TestDLLDump(testlib.HashChecker):
    """Test the dlldump module."""

    PARAMETERS = dict(
        commandline="dlldump %(pids)s --dump_dir %(tempdir)s",
        )


class TestPEDump(testlib.HashChecker):
    PARAMETERS = dict(
        commandline=("pedump --out_file %(tempdir)s/out_file.exe "
                     "--image_base %(image_base)s"),

        # This can be fetched from the output of modules plugin.
        image_base=0xf5fce000,
        )
