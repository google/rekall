# Rekall Memory Forensics
#
# Copyright 2013 Google Inc. All Rights Reserved.
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

Rekall Memory Forensics tests have these goals:

- Detect regression bugs with previous versions of Rekall Memory Forensics.

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
can write a baseline for all the modules by issuing the make_suite binary. The
baseline for each module will generate a number of files in a given directory.

When test is run, the baseline files are loaded and copared with present output
in a specific way.

"""
import hashlib
import logging
import re
import subprocess
import pdb
import os
import shutil
import sys
import tempfile
import unittest

from rekall import plugin
from rekall import registry
from rekall import session as rekall_session


class RekallBaseUnitTestCase(unittest.TestCase):
    """Base class for all rekall unit tests."""
    __metaclass__ = registry.MetaclassRegistry
    __abstract = True

    # The parameters to run this test with. These parameters are written to the
    # config file when creating a new blank template. Users can edit the config
    # file to influence how the test is run.

    PARAMETERS = {
        # This is the command line which is used to run the test.
        "commandline": "",
        }

    PLUGIN = None

    disabled = False

    @classmethod
    def is_active(cls, session):
        delegate_plugin = (
            plugin.Command.classes.get(cls.PLUGIN) or
            getattr(session.plugins, cls.CommandName() or "", None))

        if delegate_plugin:
            return delegate_plugin.is_active(session)

    @classmethod
    def CommandName(cls):
        if cls.PLUGIN:
            return cls.PLUGIN

        name = cls.PARAMETERS.get("commandline", "").split()
        if name:
            return name[0]

    def __init__(self, method_name="__init__", baseline=None, current=None,
                 debug=False, temp_directory=None):

        self.baseline = baseline
        self.current = current
        self.debug = debug
        self.temp_directory = temp_directory
        super(RekallBaseUnitTestCase, self).__init__(method_name)

    def TransformOutput(self, config_options, output):
        # Force the output to be unicode by default. Overridable by a specific
        # test.
        if not config_options.get("binary"):
            output = output.decode("utf8", "ignore")

        # Apply this transformation to the data.
        regexes = config_options.get("replace_regex")
        if regexes:
            for regex in regexes.splitlines():
                if not regex:
                    continue

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
        """Launches the rekall executable with the config specified.

        Returns:
          A baseline data structure which contains meta data from running
          rekall over the test case.
        """
        tmp_filename = os.path.join(self.temp_directory,
                                    "." + self.__class__.__name__)

        baseline_commandline = config_options.get("commandline")

        # Nothing to do here.
        if not baseline_commandline:
            return {}

        # The command line is specified in the test's PARAMETERS dict.
        try:
            baseline_commandline = baseline_commandline % config_options
        except KeyError, e:
            logging.critical(
                "Test %s requires parameter %s to be set in config file.",
                config_options["test_class"], e)
            return {}

        if baseline_commandline:
            for k, v in config_options.items():
                # prepend all global options to the command line.
                if k.startswith("-"):
                    baseline_commandline = "%s '%s' %s" % (
                        k, v, baseline_commandline)

            cmdline = config_options["executable"] + " " + baseline_commandline
            logging.debug("%s: Launching %s", self.__class__.__name__, cmdline)

            config_options["executed_command"] = cmdline

            with open(tmp_filename, "wb") as output_fd:
                pipe = subprocess.Popen(cmdline, shell=True,
                                        stdout=output_fd, stderr=output_fd)

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

        return rekall_session.Session(**args)

    def ExtractColumn(self, lines, column, skip_headers=0, seperator=r"\|\|"):
        """Iterates over the lines and extracts the column number specified.

        Args:
           lines: The output lines.
           column: The column to split off.
           skip_headers: Any header lines to skip.
        """
        for i, line in enumerate(lines):
            if i < skip_headers:
                continue

            try:
                yield re.split(seperator, line)[column].strip()
            except IndexError:
                pass

    def CompareColumns(self, previous, previous_column, current, current_column,
                       skip_headers=0):
        current_column = sorted(
            self.ExtractColumn(
                current['output'], current_column, skip_headers=skip_headers))

        previous_column = sorted(
            self.ExtractColumn(
                previous['output'], previous_column, skip_headers=skip_headers))

        self.assertEqual(current_column, previous_column)

    def assertListEqual(self, a, b, msg=None):
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
        if result is None:
            result = self.defaultTestResult()

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

                result.addError(self, sys.exc_info())
                return

            ok = False
            try:
                testMethod()
                ok = True
            except self.failureException:
                if self.debug:
                    pdb.post_mortem()

                result.addFailure(self, sys.exc_info())
            except KeyboardInterrupt:
                raise
            except Exception:
                if self.debug:
                    pdb.post_mortem()

                result.addError(self, sys.exc_info())

            try:
                self.tearDown()
            except KeyboardInterrupt:
                raise
            except Exception:
                if self.debug:
                    pdb.post_mortem()

                result.addError(self, sys.exc_info())
                ok = False
            if ok:
                result.addSuccess(self)
        finally:
            result.stopTest(self)


class SimpleTestCase(RekallBaseUnitTestCase):
    """A simple test which just compares with the baseline output."""

    __abstract = True

    def testCase(self):
        previous = self.baseline['output']
        current = self.current['output']

        # Compare the entire table
        self.assertEqual(previous, current)


class DisabledTest(RekallBaseUnitTestCase):
    """Disable a test."""
    disabled = True


class TempDirectory(object):
    """A self cleaning temporary directory."""

    def __enter__(self):
        self.name = tempfile.mkdtemp()

        return self.name

    def __exit__(self, exc_type, exc_value, traceback):
        shutil.rmtree(self.name, True)


class HashChecker(RekallBaseUnitTestCase):
    """A test comparing the hashes of all the files dumped in the tempdir."""

    def BuildBaseLineData(self, config_options):
        """We need to calculate the hash of the image we produce."""
        baseline = super(HashChecker, self).BuildBaseLineData(config_options)
        baseline['hashes'] = {}
        for filename in os.listdir(self.temp_directory):
            if not filename.startswith("."):
                with open(os.path.join(self.temp_directory, filename)) as fd:
                    md5 = hashlib.md5(fd.read())
                    baseline['hashes'][filename] = md5.hexdigest()

        return baseline

    def testHashes(self):
        self.assertEqual(self.baseline['hashes'], self.current['hashes'])
