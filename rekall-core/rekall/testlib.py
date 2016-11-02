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
import subprocess
import pdb
import os
import shutil
import sys
import tempfile
import time
import threading
import unittest

from rekall import config
from rekall import plugin
from rekall import registry
from rekall import session as rekall_session


class Tail(threading.Thread):
    """Tail a file and write to stdout."""

    def __init__(self, filename, *args, **kwargs):
        super(Tail, self).__init__(*args, **kwargs)
        self.fd = open(filename, "rb")
        self.running = False
        self.daemon = True

    def start(self):
        self.running = True
        super(Tail, self).start()

    def stop(self):
        if self.running:
            self.running = False
            self.join()

    def run(self):
        while self.running:
            time.sleep(0.1)

            while True:
                data = self.fd.read(1000)
                if not data:
                    break

                sys.stdout.write(data)
                sys.stdout.flush()


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

    temp_directory = None

    @classmethod
    def is_active(cls, _):
        return True

    @classmethod
    def CommandName(cls):
        if cls.PLUGIN:
            return cls.PLUGIN

        name = cls.PARAMETERS.get("commandline", "").split()
        if name:
            return name[0]

    def __init__(self, method_name="__init__", baseline=None, current=None,
                 debug=False, temp_directory=None, config_options=None):
        super(RekallBaseUnitTestCase, self).__init__(method_name)
        self.baseline = baseline
        self.config_options = config_options
        self.current = current
        self.debug = debug
        if temp_directory:
            self.temp_directory = temp_directory
        super(RekallBaseUnitTestCase, self).__init__(method_name)

    @classmethod
    def setUpClass(cls):
        super(RekallBaseUnitTestCase, cls).setUpClass()
        if cls.temp_directory is None:
            cls.temp_directory = tempfile.mkdtemp()

    @classmethod
    def tearDownClass(cls):
        super(RekallBaseUnitTestCase, cls).tearDownClass()
        if cls.temp_directory:
            shutil.rmtree(cls.temp_directory, True)

    def setUp(self):
        self.session = self.MakeUserSession()

    def LaunchExecutable(self, config_options):
        """Launches the rekall executable with the config specified.

        Returns:
          A baseline data structure which contains meta data from running
          rekall over the test case.
        """
        config_options = config_options.copy()
        tmp_filename = os.path.join(self.temp_directory,
                                    "." + self.__class__.__name__)
        error_filename = tmp_filename + ".stderr"

        baseline_commandline = config_options.get("commandline")
        config_options["tempdir"] = self.temp_directory

        # Nothing to do here.
        if not baseline_commandline:
            return {}

        # The command line is specified in the test's PARAMETERS dict.
        try:
            baseline_commandline = baseline_commandline % config_options
        except KeyError as e:
            logging.critical(
                "Test %s requires parameter %s to be set in config file. (%s)",
                config_options["test_class"], e, baseline_commandline)
            return {}

        if baseline_commandline:
            baseline_commandline = "- %s" % baseline_commandline
            for k, v in config_options.items():
                # prepend all global options to the command line.
                if k.startswith("-"):
                    # This is a boolean flag.
                    if v is True:
                        baseline_commandline = "%s %s" % (
                            k, baseline_commandline)

                    elif isinstance(v, list):
                        baseline_commandline = "%s %s %s" % (
                            k, " ".join("'%s'" % x for x in v),
                            baseline_commandline)

                    else:
                        baseline_commandline = "%s '%s' %s" % (
                            k, v, baseline_commandline)

            cmdline = (config_options["executable"] + " -v " +
                       baseline_commandline)
            logging.debug("%s: Launching %s", self.__class__.__name__, cmdline)

            # Make sure the subprocess does not buffer so we can catch its
            # output in a timely manner.
            os.environ["PYTHONUNBUFFERED"] = "1"

            with open(tmp_filename, "wb", buffering=1) as output_fd:
                with open(error_filename, "wb", buffering=1) as error_fd:
                    stdout_copier = Tail(tmp_filename)
                    stderr_copier = Tail(error_filename)
                    # Specifying --debug should allow the subprocess to print
                    # messages directly to stdout. This is useful in order to
                    # attach a breakpoint (e.g. in an inline test).
                    if config_options.get("debug"):
                        stderr_copier.start()
                        stdout_copier.start()

                    pipe = subprocess.Popen(cmdline, shell=True,
                                            stdout=output_fd, stderr=error_fd)

                    pipe.wait()

                    # Done running the command, now prepare the json baseline
                    # file.
                    output_fd.flush()
                    error_fd.flush()
                    stdout_copier.stop()
                    stderr_copier.stop()

            output = open(tmp_filename).read(10 * 1024 * 1024)
            output = output.decode("utf8", "ignore")

            error = open(error_filename).read(10 * 1024 * 1024)
            error = error.decode("utf8", "ignore")

            baseline_data = dict(output=output.splitlines(),
                                 logging=error.splitlines(),
                                 return_code=pipe.returncode,
                                 executed_command=cmdline)

            return baseline_data

        else:
            # No valid command line - this baseline is aborted.
            config_options["aborted"] = True

            return {}

    def BuildBaselineData(self, config_options):
        return self.LaunchExecutable(config_options)

    def MakeUserSession(self, config_options=None):
        if config_options is None:
            config_options = self.config_options or {}

        user_session = rekall_session.InteractiveSession()
        with user_session.state as state:
            config.MergeConfigOptions(state, user_session)
            for k, v in config_options.items():
                if k.startswith("--"):
                    state.Set(k[2:], v)

        return user_session

    def assertListEqual(self, a, b, msg=None):
        a = list(a)
        b = list(b)
        self.assertEqual(len(a), len(b))

        for x, y in zip(a, b):
            self.assertEqual(x, y)

    def __unicode__(self):
        return "%s %s" % (self.__class__.__name__, self._testMethodName)

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


class SimpleTestCase(plugin.ModeBasedActiveMixin,
                     RekallBaseUnitTestCase):
    """A simple test which just compares with the baseline output."""

    __abstract = True

    @classmethod
    def is_active(cls, session):
        if not super(SimpleTestCase, cls).is_active(session):
            return False

        delegate_plugin = (
            plugin.Command.ImplementationByClass(cls.PLUGIN) or
            getattr(session.plugins, cls.CommandName() or "", None))

        if delegate_plugin:
            return delegate_plugin.is_active(session)

    def testCase(self):
        previous = sorted(self.baseline['output'])
        current = sorted(self.current['output'])

        # Compare the entire table
        self.assertListEqual(previous, current)


class InlineTest(SimpleTestCase):
    # Override this to make this script run in the interactive shell in a
    # subprocess.
    script = "print 1"

    def LaunchExecutable(self, config_options):
        tmp_script = os.path.join(self.temp_directory, "script.py")
        with open(tmp_script, "w") as fd:
            fd.write("tempdir = %r\n" % self.temp_directory)
            fd.write(self.script)

        config_options["commandline"] = "run --run %s" % tmp_script
        config_options["script"] = self.script.splitlines()
        return super(InlineTest, self).LaunchExecutable(config_options)


class SortedComparison(SimpleTestCase):
    """All test cases are sorted now."""


class UnSortedComparison(SimpleTestCase):

    __abstract = True

    def testCase(self):
        previous = self.baseline['output']
        current = self.current['output']

        # Compare the entire table
        self.assertEqual(previous, current)


class DisabledTest(RekallBaseUnitTestCase):
    """Disable a test."""
    disabled = True

    @classmethod
    def is_active(cls, _):
        return False


class HashChecker(SimpleTestCase):
    """A test comparing the hashes of all the files dumped in the tempdir."""

    def BuildBaselineData(self, config_options):
        """We need to calculate the hash of the image we produce."""
        baseline = super(HashChecker, self).BuildBaselineData(config_options)
        baseline['hashes'] = {}
        for filename in os.listdir(self.temp_directory):
            if not filename.startswith("."):
                with open(os.path.join(self.temp_directory, filename)) as fd:
                    md5 = hashlib.md5()
                    while 1:
                        data = fd.read(1024 * 1024)
                        if not data:
                            break

                        md5.update(data)

                    baseline['hashes'][filename] = md5.hexdigest()

        return baseline

    def testCase(self):
        self.assertEqual(self.baseline['hashes'], self.current['hashes'])


main = unittest.main
