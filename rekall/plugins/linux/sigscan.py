# Rekall Memory Forensics
# Copyright 2015 Google Inc. All Rights Reserved.
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

from rekall import testlib
from rekall.plugins.common import sigscan
from rekall.plugins.linux import common


class LinuxSigScan(sigscan.SigScanMixIn, common.LinProcessFilter):
  """Runs a signature scans against physical, kernel or process memory."""
  pass


class TestLinuxSigScanPhysical(testlib.SimpleTestCase):
    """Runs sigscan against physical memory."""

    PARAMETERS = dict(commandline="sigscan %(signature)s --scan_physical",
                      signature="")


class TestLinuxSigScanKernel(testlib.SimpleTestCase):
    """Runs sigscan against the kernel."""

    PARAMETERS = dict(commandline="sigscan %(signature)s --scan_kernel",
                      signature="")


class TestLinuxSigScanProcess(testlib.SimpleTestCase):
    """Runs sigscan against processes."""

    PARAMETERS = dict(
        commandline="sigscan %(signature)s --proc_regex %(proc_regex)s",
        signature="",
        proc_regex=".")
