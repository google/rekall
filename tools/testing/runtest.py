# Volatility
#
# Authors:
# Michael Cohen <scudette@users.sourceforge.net>
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

"""Compares run output from the previous test run result directories."""

import argparse
import unittest

from volatility import testlib
from volatility import plugins
from volatility.plugins import tests


parser =  argparse.ArgumentParser()
parser.add_argument("path", nargs=1,
                    help="The path to the previous test result.")

parser.add_argument("test", nargs="?",
                    help="The test to run e.g. TestSuite.testMethod. "
                    "If missing we run all the tests.")


if __name__ == "__main__":
    FLAGS = parser.parse_args()
    test_program = testlib.VolatilityTestProgram(FLAGS)
