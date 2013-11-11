# Volatility
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
import os
import hashlib
import StringIO

from volatility import testlib


class TestProcdump(testlib.VolatilityBaseUnitTestCase):
    """Test the Procdump module."""

    PARAMETERS = dict(
        ng_commandline="procdump --pid 2536 --dump-dir %(tempdir)s",
        trunk_commandline="procexedump --pid 2536 --dump-dir %(tempdir)s",
        pid=2536)

    def BuildBaseLineData(self, config_options):
        """We need to calculate the hash of the image we produce."""
        baseline = super(TestProcdump, self).BuildBaseLineData(config_options)

        # Filename should be stored in the temp directory and have a name which
        # ends with the pid:

        filenames = [x for x in os.listdir(self.temp_directory)
                     if x.endswith("%s.exe" % config_options['pid'])]

        self.assertEqual(len(filenames), 1)

        with open(os.path.join(self.temp_directory, filenames[0])) as fd:
            md5 = hashlib.md5(fd.read())
            baseline['hash'] = md5.hexdigest()

        return baseline

    def testProcDump(self):
        self.assertEqual(self.baseline['hash'], self.current['hash'])


class TestDLLDump(testlib.VolatilityBaseUnitTestCase):
    """Test the dlldump module."""

    PARAMETERS = dict(commandline="dlldump --pid 4012 --dump-dir %(tempdir)s",
                      pid=4012)

    def BuildBaseLineData(self, config_options):
        """We need to calculate the hash of the image we produce."""
        baseline = super(TestDLLDump, self).BuildBaseLineData(config_options)

        # Filename should be stored in the temp directory and have a name which
        # ends with the pid:

        filenames = sorted(
            [x for x in os.listdir(self.temp_directory)
             if x.startswith("module.%s" % config_options['pid'])])

        baseline['hashes'] = []
        for filename in filenames:
            with open(os.path.join(self.temp_directory, filename)) as fd:
                md5 = hashlib.md5(fd.read())
                baseline['hashes'].append(md5.hexdigest())

        return baseline

    def testProcDump(self):
        self.assertEqual(self.baseline['hashes'],
                         self.current['hashes'])
