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

    trunk_launch_args = [['printkey']]
    ng_launch_args = [['printkey', {}]]

    def testPrintkey(self):
        """Tests the printkey module."""
        previous, current = self.ReRunVolatilityTest('printkey')

        if previous.get('mode') == 'trunk':
            for i, line in enumerate(current['output']):
                current['output'][i] = re.sub(r"(Registry: [^@]+) @ .+", r"\1", line)

        previous_blocks = sorted(self.SplitLines(previous['output'], "----------"))
        current_blocks = sorted(self.SplitLines(current['output'], "----------"))

        for x, y in zip(previous_blocks, current_blocks):
            self.assertEqual(x, y)


class TestRegDump(testlib.VolatilityBaseUnitTestCase):
    """Test dumping of registry hives."""

    ng_launch_args = [['regdump', {}]]

    def RunVolatilityModule(self, **kwargs):
        # Get a temp directory
        with testlib.TempDirectory() as directory:
            result = super(TestRegDump, self).RunVolatilityModule(
                dump_dir=directory, **kwargs)

            result['hashes'] = {}
            for filename in os.listdir(directory):
                md5 = hashlib.md5()
                with open(os.path.join(directory, filename), "rb") as fd:
                    data = fd.read(1024*1024)
                    if not data: break
                    md5.update(data)

                result['hashes'][filename] = md5.hexdigest()

        return result

    def testRegDump(self):
        try:
            previous_run_data = self.LoadPreviousRunData('regdump')
        except IOError:
            logging.warn("No baseline for regdump skipping.")
            return

        result = self.RunVolatilityModule(profile=previous_run_data['profile'],
                                          image=previous_run_data['filename'],
                                          module='regdump')

        self.assertEqual(previous_run_data['hashes'], result['hashes'])

