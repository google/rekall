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
import re
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
