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

- Detect regression bugs with previous versions of Volatility NG.

- Detect differences between Volatility 2.X trunk and Volatility NG.

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
baseline for each module can be written for either volatility NG or Volatility
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
import sys
import unittest
import StringIO

from volatility import registry
from volatility import session


class VolatilityBaseUnitTestCase(unittest.TestCase):
    """Base class for all volatility unit tests."""
    __metaclass__ = registry.MetaclassRegistry
    __abstract = True

    def __init__(self, method_name="__init__"):
        super(VolatilityBaseUnitTestCase, self).__init__(method_name)

    def defaultTestResult(self):
        return VolatilityTestResult()

    def LoadPreviousRunData(self, module):
        # Module names are only lower case letters
        if re.search("[^a-z_]", module):
            raise AttributeError("Module name is not valid.")

        data = json.loads(
            open(os.path.join(self.flags.path[0], module)).read(10 * 1024 * 1024))

        # Try to apply the patch.
        try:
            patch = json.loads(
                open(os.path.join(self.flags.path[0], module + ".patch")).read(
                    10 * 1024 * 1024))
            self.ApplyPatch(patch, data)
        except IOError:
            pass

        return data

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

    def SaveRunData(self, path, module_name, data):
        # Module names are only lower case letters
        if re.search("[^a-z_]", module_name):
            raise AttributeError("Module name is not valid.")

        with open(os.path.join(path, module_name), "w") as fd:
            logging.info("Writing %s" % fd.name)
            fd.write(json.dumps(data, indent=4))

    def BuildUserSession(self, module):
        """Creates a new session object for testing."""
        previous_run_data = self.LoadPreviousRunData(module)

        user_session = session.Session()
        user_session.filename = previous_run_data['filename']
        user_session.profile = previous_run_data['profile']
        return user_session

    def LaunchTrunkVolatility(self, executable=None, profile=None, image=None,
                              args=None, **kwargs):
        """Launches the Volatility trunk binary.

        Launches external binary and capture its output into a metadata dict.
        """
        if args is None:
            args = []

        args = [executable, "--profile", profile, "--file", image] + args
        metadata = {}

        t = time.time()
        logging.info("Launching %s" % (args,))
        pipe = subprocess.Popen(args, stderr=subprocess.PIPE,
                                stdout=subprocess.PIPE)

        output, err = pipe.communicate()

        # Just a simple measure of time, so we can detect extreme slow down
        # regressions.
        metadata['time_used'] = time.time() - t
        logging.info("Completed in %s seconds" % metadata['time_used'])

        metadata['output'] = output.splitlines()
        metadata['number_of_lines'] = len(metadata['output'])
        metadata['profile'] = profile
        metadata['filename'] = image
        metadata['mode'] = "trunk"

        return metadata

    def RunVolatilityModule(self, profile=None, image=None, module=None, **kwargs):
        """Runs the module and generates metada describing the test."""
        # Module names are only lower case letters
        if re.search("[^a-z_]", module):
            raise AttributeError("Module name is not valid.")

        t = time.time()
        user_session = session.Session(filename=image, profile=profile)
        fd = StringIO.StringIO()
        user_session.vol(module, fd=fd, **kwargs)

        # Just a simple measure of time, so we can detect extreme slow down
        # regressions.
        metadata = dict(output = fd.getvalue().splitlines())

        metadata['time_used'] = time.time() - t
        logging.info("Completed in %s seconds" % metadata['time_used'])

        metadata['number_of_lines'] = len(metadata['output'])
        metadata['profile'] = profile
        metadata['filename'] = image
        metadata['mode'] = 'ng'
        metadata['kwargs'] = kwargs

        return metadata

    def ExtractColumn(self, lines, column, skip_headers=0, seperator=r"\|\|"):
        """Iterates over the lines and extracts the column number specified.

        Args:
           lines: The output lines.
           column: The column to split off.
           skip_headers: Any header lines to skip.
        """
        for line in lines[skip_headers:]:
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

    def ReRunVolatilityTest(self, module, **kwargs):
        """Loads and reruns the test stored in this module baseline file.

        Note that we use the metadata stored in the baseline file to rerun this
        test.
        """
        previous_run_data = self.LoadPreviousRunData(module)
        current_run_data = self.RunVolatilityModule(
            profile=previous_run_data['profile'],
            image=previous_run_data['filename'],
            module=module, **previous_run_data.get('kwargs', kwargs))

        return previous_run_data, current_run_data


    trunk_launch_args = []
    def MakeBaseLineFromTrunk(self, executable=None, image=None, path=None,
                              profile=None, modules=None, **kwargs):
        """Same as MakeBaseLine except we need to generate this from Trunk.

        Usually this means launching the trunk program externally.

        Args:
          executable: Use this executable to launch the binary.
          image: The image that will be tested.
          path: The path which the baseline metadata files are written in.
          profile: The profile to use.
          modules: If set, only run modules in this set.
        """
        for args in self.trunk_launch_args:
            module = args[0]

            # Skip it if we dont need it.
            if modules and module not in modules: continue

            metadata = self.LaunchTrunkVolatility(executable=executable, profile=profile,
                                                  image=image, args=args)

            self.SaveRunData(path, module, metadata)

    ng_launch_args = []
    def MakeBaseLine(self, image=None, path=None, profile=None, modules=None,
                     **kwargs):
        """Create all baseline files in path.

        This should be extended by TestCases to set up their baselines.

        Args:
           image: The image file to operate on.
           path: The directory path to store the baseline file.
           profile: The profile to use.
           modules: only run these modules.
        """
        for module, kwargs in self.ng_launch_args:
            # Skip it if we dont need it.
            if modules and module not in modules: continue

            metadata = self.RunVolatilityModule(profile=profile, image=image,
                                                module=module, **kwargs)
            self.SaveRunData(path, module, metadata)

    def assertListEqual(self, a, b):
        a = list(a)
        b = list(b)
        self.assertEqual(len(a), len(b))

        for x, y in zip(a, b):
            self.assertEqual(x, y)

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


class VolatilityTestLoader(unittest.TestLoader):
    """A test suite loader which searches for tests in all the plugins."""

    # We load all tests extending this class.
    base_class = VolatilityBaseUnitTestCase

    def __init__(self, flags):
        super(VolatilityTestLoader, self).__init__()
        self.flags = flags

    def loadTestsFromModule(self, _):
        """Just return all the tests as if they were in the same module."""
        test_cases = [
            self.loadTestsFromTestCase(x) for x in self.base_class.classes.values()]
        return self.suiteClass(test_cases)

    def loadTestsFromTestCase(self, testCaseClass):
        result = super(VolatilityTestLoader, self).loadTestsFromTestCase(testCaseClass)

        # Attach the flags to the test suites.
        testCaseClass.flags = self.flags

        return result

    def loadTestsFromName(self, name, module=None):
        """Load the tests named."""
        parts = name.split(".")
        test_cases = self.loadTestsFromTestCase(self.base_class.classes[parts[0]])

        # Specifies the whole test suite.
        if len(parts) == 1:
            return self.suiteClass(test_cases)
        elif len(parts) == 2:
            cls = self.base_class.classes[parts[0]]
            return unittest.TestSuite([cls(parts[1])])


class VolatilityTestResult(unittest._TextTestResult):
    def addError(self, test, err):
        pdb.post_mortem(err[2])
        super(VolatilityTestResult, self).addFailure(test, err)

    def addFailure(self, test, err):
        pdb.post_mortem(err[2])
        super(VolatilityTestResult, self).addFailure(test, err)


class VolatilityTestRunner(unittest.TextTestRunner):
    def _makeResult(self):
        return VolatilityTestResult(self.stream, self.descriptions, self.verbosity)


class VolatilityTestProgram(unittest.TestProgram):
    def __init__(self, flags):
        argv = [sys.argv[0]]
        if flags.test:
            argv.append(flags.test)

        super(VolatilityTestProgram, self).__init__(
            testRunner=VolatilityTestRunner(),
            argv=argv, testLoader=VolatilityTestLoader(flags))

