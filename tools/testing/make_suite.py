# Volatility
#
# Authors:
# Michael Cohen <scudette@users.sourceforge.net>
# Copyright (c) 2012
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

"""This script creates a new test suite result directory.

A result directory is simply the output of a plugin for each plugin in
its own file.

This script is used to update the "known good" configuration. Regressions are
then detected as differences against this "known good" result.
"""

import argparse
import time
import subprocess
import json
import re
import os
import logging

from volatility import testlib

# Bring in all the tests
from volatility.plugins import tests



parser =  argparse.ArgumentParser()
parser.add_argument("image", nargs=1,
                    help="The image path to read.")

parser.add_argument("path", nargs=1,
                    help="The path to create output baseline files in.")

parser.add_argument("-e", "--executable", default=None,
                    help="The path to the trunk binary. If specified we generate "
                    "trunk baseline files.")

parser.add_argument("-p", "--profile", default="WinXPSP2x86",
                    help="The profile to use.")

if __name__ == "__main__":
    logging.getLogger().setLevel(logging.INFO)
    FLAGS = parser.parse_args()

    # Generate baselines for all the tests.
    for case, case_cls in testlib.VolatilityBaseUnitTestCase.classes.items():
        logging.info("Generating baseline for test %s" % case)

        # Generate trunk baselines.
        if FLAGS.executable:
            case_cls().MakeBaseLineFromTrunk(FLAGS.executable, FLAGS.image[0],
                                             FLAGS.path[0], FLAGS.profile)
        else:
            case_cls().MakeBaseLine(FLAGS.image[0], FLAGS.path[0], FLAGS.profile)
