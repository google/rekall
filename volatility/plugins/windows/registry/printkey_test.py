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

"""Tests for the printkey plugin."""
import hashlib
import re
import os

from volatility import testlib


class TestPrintkey(testlib.VolatilityBaseUnitTestCase):
    """Test the printkey module."""

    PARAMETERS = dict(commandline="printkey")

    def testPrintkey(self):
        """Tests the printkey module."""
        previous = self.baseline['output']
        current = self.current['output']

        if self.baseline_mode == 'trunk':
            for i, line in enumerate(current):
                current[i] = re.sub(
                    r"(Registry: [^@]+) @ .+", r"\1", line)

        previous_blocks = sorted(
            self.SplitLines(previous, "----------"))

        current_blocks = sorted(
            self.SplitLines(current, "----------"))

        for x, y in zip(previous_blocks, current_blocks):
            self.assertEqual(x, y)


class TestRegDump(testlib.VolatilityBaseUnitTestCase):
    """Test dumping of registry hives."""

    PARAMETERS = dict(ng_commandline="regdump --dump-dir %(tempdir)s")

    def BuildBaseLineData(self, config_options):
        """We need to calculate the hash of the image we produce."""
        baseline = super(TestRegDump, self).BuildBaseLineData(config_options)

        # Filename should be stored in the temp directory and have a name which
        # ends with the pid:

        filenames = sorted(
            [x for x in os.listdir(self.temp_directory) if "@" in x])

        baseline['hashes'] = []
        for filename in filenames:
            with open(os.path.join(self.temp_directory, filename)) as fd:
                md5 = hashlib.md5(fd.read())
                baseline['hashes'].append(md5.hexdigest())

        return baseline

    def testRegDump(self):
       self.assertEqual(self.baseline['hashes'], self.current['hashes'])

