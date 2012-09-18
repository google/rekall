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

"""Base classes for all tests.

Volatility tests have these goals:

- Detect regression bugs with previous versions of Volatility.

- Detect differences between Volatility 2.X trunk and Volatility TP.

- Once differences are detected, make it easier to understand why the
  differences arise.

- Sometime the differences are acceptable, in that case, there need to be a way
  to declare the allowed differences in the tests.

- What makes this more complicated is that the same test needs to be applied to
  multiple images in a consistent way without necessarily making any code
  changes to the test itself.


Solution Outline
----------------

A baseline of running each test is written by the test suite itself. The user
can write a baseline for all the modules by issuing the make_suite binary. A
baseline for each module can be written for either volatility TP or Volatility
2.x (trunk). The baseline for each module will generate a number of files in a
given directory.

When test is run, the baseline files are loaded and copared with present output
in a specific way.

"""
import json
import time
import logging
import re
import subprocess
import pdb
import os
import shutil
import sys
import tempfile
import unittest
import StringIO

from volatility import registry
from volatility import session
from volatility.ui import renderer


class VolatilityBaseUnitTestCase(unittest.TestCase):
    """Base class for all volatility unit tests."""
    __metaclass__ = registry.MetaclassRegistry
    __abstract = True

    PARAMETERS = {}

    def __init__(self, method_name="__init__", baseline=None, current=None,
                 debug=False, temp_directory=None, running_mode="ng"):
        self.baseline = baseline
        self.current = current
        self.debug = debug
        self.temp_directory = temp_directory

        # The mode of this test indicates which version of Volatility is
        # used. It can be either "ng" for the tech preview version, or "trunk"
        # for the old version.  We need to know the mode in two contexts - the
        # baseline_mode is the mode which was used to generate the baseline,
        # while the running_mode is the mode for the current run.

        # The mode is used in order to intelligently compare output from the two
        # versions.
        self.running_mode = running_mode
        if baseline:
            self.baseline_mode = self.baseline['options']['mode']
        else:
            self.baseline_mode = self.running_mode

        super(VolatilityBaseUnitTestCase, self).__init__(method_name)

    def TransformOutput(self, config_options, output):
        # Force the output to be unicode by default. Overridable by a specific
        # test.
        if not config_options.get("binary"):
            output = output.decode("utf8", "ignore")

        # Apply this transformation to the data.
        regexes = config_options.get("%s_replace_regex" % self.running_mode)
        if regexes:
            for regex in regexes.splitlines():
                if not regex: continue

                separator = regex[1]
                parts = regex.split(separator)
                if parts[0] != "s" or len(parts) != 4:
                    raise RuntimeError("Regex transform invalid: %s" % regex)

                output = re.sub(parts[1], parts[2], output)

        return output

    def ApplyPatch(self, patch, data):
        for k, v in patch.items():
            item = data[k]
            for patch_action in v:
                operation, line_number, new_values = patch_action[:3]
                if operation == "insert":
                    item.insert(line_number, new_values)
                elif operation == "delete":
                    item.pop(line_number)
                elif operation == "replace":
                    item[line_number] = new_values
                else:
                    logging.warn("Unknown patch action %s" % operation)

    def LaunchExecutable(self, config_options):
        """Launches the volatility executable with the config specified.

        Returns:
          A baseline data structure which contains meta data from running
          volatility over the test case.
        """
        tmp_filename = os.path.join(self.temp_directory, self.__class__.__name__)

        # A different command line can be specified for each mode.
        baseline_commandline = (
            config_options.get("%s_commandline" % self.running_mode) or
            config_options.get("commandline"))

        if baseline_commandline:
            for k, v in config_options.items():
                # prepend all global options to the command line.
                if k.startswith("-"):
                    baseline_commandline = "%s '%s' %s" % (k, v, baseline_commandline)

            cmdline = config_options["executable"] + " " + baseline_commandline
            logging.debug("%s: Launching %s", self.__class__.__name__, cmdline)

            config_options["executed_command"] = baseline_commandline

            with open(tmp_filename, "wb") as output_fd:
                pipe = subprocess.Popen(cmdline, shell=True, stdout=output_fd)

                pipe.wait()

                # Done running the command, now prepare the json baseline file.
                output_fd.flush()

                output = self.TransformOutput(
                    config_options, open(tmp_filename).read(10 * 1024 * 1024))

                baseline_data = dict(output=output.splitlines())

                return baseline_data

        else:
            # No valid command line - this baseline is aborted.
            config_options["aborted"] = True

            return {}

    def BuildBaseLineData(self, config_options):
        return self.LaunchExecutable(config_options)

    def MakeUserSession(self, config_options):
        args = {}
        for k, v in config_options.items():
            if k.startswith("--"):
                args[k[2:]] = v

        return session.Session(**args)

    def ExtractColumn(self, lines, column, skip_headers=0, seperator=r"\|\|"):
        """Iterates over the lines and extracts the column number specified.

        Args:
           lines: The output lines.
           column: The column to split off.
           skip_headers: Any header lines to skip.
        """
        for i, line in enumerate(lines):
            if i < skip_headers: continue

            try:
                yield re.split(seperator, line)[column].strip()
            except IndexError: pass

    def CompareColumns(self, previous, previous_column, current, current_column,
                       skip_headers=0):
        current_column = sorted(
            self.ExtractColumn(
                current['output'], current_column, skip_headers=skip_headers))

        previous_column = sorted(
            self.ExtractColumn(
                previous['output'], previous_column, skip_headers=skip_headers))

        self.assertEqual(current_column, previous_column)

    def assertListEqual(self, a, b):
        a = list(a)
        b = list(b)
        self.assertEqual(len(a), len(b))

        for x, y in zip(a, b):
            self.assertEqual(x, y)

    def assertTableRowsEqual(self, a, b):
        a = [x.strip() for x in a.split("||")]
        b = [x.strip() for x in b.split("||")]
        self.assertEqual(a, b)

    def assertIntegerListEqual(self, a, b, base=16):
        """Compares two list of printed integers."""
        a = [int(x, base) for x in a]
        b = [int(x, base) for x in b]
        self.assertEqual(len(a), len(b))

        for x, y in zip(a, b):
            self.assertEqual(x, y)

    def SplitLines(self, output, seperator="********"):
        section = []
        for line in output:
            if seperator in line:
                if section:
                    yield section
                    section = []

            section.append(line)
        yield section

    def ReplaceOutput(self, search_regex, replace, output):
        return [re.sub(search_regex, replace, x) for x in output]

    def FilterOutput(self, output, regex, exclude=False):
        """Filter the output lines using a regex."""
        regex_c = re.compile(regex)
        result = []
        for line in output:
            m = regex_c.search(line)

            if exclude:  # Remove lines that match.
                if m is None:
                    result.append(line)

            else:  # Only include lines that match
                if m:
                    result.append(line)

        return result

    def MatchOutput(self, output, regex, group=0):
        regex_c = re.compile(regex)

        for line in output:
            m = regex_c.search(line)
            if m:
                yield m.group(group)


    def run(self, result=None):
        if result is None: result = self.defaultTestResult()
        result.startTest(self)
        testMethod = getattr(self, self._testMethodName)
        try:
            try:
                self.setUp()
            except KeyboardInterrupt:
                raise
            except Exception:
                if self.debug:
                    pdb.post_mortem()

                result.addError(self, self._exc_info())
                return

            ok = False
            try:
                testMethod()
                ok = True
            except self.failureException:
                if self.debug:
                    pdb.post_mortem()

                result.addFailure(self, self._exc_info())
            except KeyboardInterrupt:
                raise
            except Exception:
                if self.debug:
                    pdb.post_mortem()

                result.addError(self, self._exc_info())

            try:
                self.tearDown()
            except KeyboardInterrupt:
                raise
            except Exception:
                if self.debug:
                    pdb.post_mortem()

                result.addError(self, self._exc_info())
                ok = False
            if ok: result.addSuccess(self)
        finally:
            result.stopTest(self)


class SimpleTestCase(VolatilityBaseUnitTestCase):
    """A simple test which just compares with the baseline output."""

    __abstract = True

    def testCase(self):
        previous = self.baseline['output']
        current = self.current['output']

        # Compare the entire table
        self.assertEqual(previous, current)


class TempDirectory(object):
    """A self cleaning temporary directory."""

    def __enter__(self):
        self.name = tempfile.mkdtemp()

        return self.name

    def __exit__(self, exc_type, exc_value, traceback):
        shutil.rmtree(self.name, True)
