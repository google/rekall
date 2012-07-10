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

"""Tests for the kdbgscan plugin."""

from volatility import testlib


class TestKDBGScan(testlib.VolatilityBaseUnitTestCase):
    """Test the kdbgscan module."""

    trunk_launch_args = [['kdbgscan']]
    ng_launch_args = [['kdbgscan', {}]]

    fields = ["Offset (V)", "Offset (P)", "KDBG owner tag check",
              "Version64", "Service Pack", "Build string",
              "PsActiveProcessHead", "PsLoadedModuleList", "KernelBase",
              "KPCR"]

    def ParseSection(self, section):
        result = {}
        for line in section:
            try:
                field, value = line.split(":", 1)
            except ValueError:
                continue

            for matched_field in self.fields:
                if matched_field in field:
                    result[matched_field] = value
                    break

        return result

    def testKDBGScan(self):
        previous_meta, current_meta = self.ReRunVolatilityTest('kdbgscan')
        previous = previous_meta['output']
        current = current_meta['output']

        current_sections = list(self.SplitLines(current, seperator="***********"))
        previous_sections = list(self.SplitLines(previous, seperator="***********"))

        self.assertEqual(self.ParseSection(current_sections[0]),
                         self.ParseSection(previous_sections[0]))
