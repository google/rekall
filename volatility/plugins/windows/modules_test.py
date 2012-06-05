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

"""Tests for the modules plugins."""

from volatility import testlib


class TestModules(testlib.VolatilityBaseUnitTestCase):
    """Test the Modules module."""

    trunk_launch_args = [['modules']]
    ng_launch_args = [['modules', {}]]

    # Disabled temporarily until the output is more parseable.
    def XXXtestModules(self):
        """Test the modules plugin."""
        previous_meta, current_meta = self.ReRunVolatilityTest('modules')
        previous = previous_meta['output']
        current = current_meta['output']

        # Compare virtual addresses.
        self.assertIntegerListEqual(
            sorted(self.ExtractColumn(current, 0, 2)),
            sorted(self.ExtractColumn(previous, 0, 2)))

        # Comparing against trunk we need to remap the columns a bit.
        if previous_meta['mode'] == 'trunk':
            names = sorted(self.ExtractColumn(previous, 1, 2, " +"))
            base = sorted(self.ExtractColumn(previous, 2, 2, " +"))
            path = sorted(self.ExtractColumn(previous, 1, 2, ".{54}"))
        else:
            names = sorted(self.ExtractColumn(previous, 2, 2, " +"))
            base = sorted(self.ExtractColumn(previous, 3, 2, " +"))
            path = sorted(self.ExtractColumn(previous, 2, 2, "0 +"))

        # Compare filenames.
        self.assertListEqual(
            sorted(self.ExtractColumn(current, 2, 2, " +")), names)
        self.assertListEqual(
            sorted(self.ExtractColumn(current, 2, 2, "0 +")), path)

        # Compare virtual addresses.
        self.assertIntegerListEqual(
            sorted(self.ExtractColumn(current, 3, 2, " +")), base)
