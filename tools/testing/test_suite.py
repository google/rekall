#!/usr/bin/env python

# Rekall
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Authors:
# Michael Cohen <scudette@gmail.com>
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

A result directory collects the output of tests run against a specific image in
their own file.

Tests are driven from a test suite description file, typically named
"tests.config" which is located in the same directory as the image.

How to Use this program
=======================

The test suite is specifically designed to catch regression errors, it is not
specifically designed to catch general analysis errors. Ideally analysis errors
should be detected manually, by setting up specific images with known artifacts
in them. This test suite is not designed for such purposes.

The tests are driven by a configuration file. The configuration file is
specifically tailored to a particular test image, and should be manually
adapted. We assume the provided configuation file is used as a template.

To trap regression errors, we first need to generate a baseline. The baseline
runs every plugin and records the output of the plugin in a file within the test
directory. If a baseline file is not found for a particular plugin, the program
will automatically create a new baseline file. However, if a baseline file
already exists, the program will compare the output of the current run to the
baseline. Here is an example execution where TestLsmod has rebuilt its baseline,
and TestCpuInfo has failed:

$ test_suite.py baseline -c test_data/ubuntu_8.04/tests.config

Test                             Status   Time Expected Time Error File
------------------------------ ---------- ---- ------------- ----------
TestLinuxFindDTB               PASS      2.49    2.49
TestLsmod                      REBUILT   3.22
TestVtoP                       PASS      3.28    1.00
TestCpuInfo                    FAIL      3.12    2.22
TestCheckAFInfo                PASS      3.21    1.25
TestArp                        PASS      4.23    4.23

It is possible to run specific tests by naming them at the command line:
$ test_suite.py -c test_data/ubuntu_8.04/tests.config TestCpuInfo TestVtoP
Test                             Status   Time Expected Time Error File
------------------------------ ---------- ---- ------------- ----------
TestCpuInfo                    PASS   1.39    0.98
TestVtoP                       PASS   1.63    1.00

Sometimes although the output of the plugin has changed, the plugin is still
correct. In that case the test will fail and will need to be manually
reviewed. If the plugin is deemed to be still correct, we can force the baseline
to be updated by specifying the --baseline (or -b) flag:

test_suite.py test -c test_data/xp-laptop-2005-06-25/tests.config TestCpuInfo -b

Test                             Status   Time Expected Time Error File
------------------------------ ---------- ---- ------------- ----------
TestCpuInfo                    REBUILT   0.98

How tests are chosen
====================

Since the goal of this test suite is only to detect regressions, there is no
need to write specialized test for each plugin. If no specific test for a
plugin is found, the test suite will simply create one based on the
testlib.SimpleTestCase() class - i.e. it just literally compares the output of
the plugin. In most cases this is what we want.

Sometimes, however, we want fine grained control over the test execution. In
that case we need to create a test class within the codebase which extends the
testlib.RekallBaseUnitTestCase(). We can specify the command line for
executing the test thus:

class TestCheckTaskFops(testlib.SimpleTestCase):
    PARAMETERS = dict(
        commandline="check_task_fops --all"
        )

More complex examples may use custom or more sophisticated methods for comparing
the plugin output. For example the testlib.HashChecker() base class will ensure
that all files produced by a plugin retain their hashes between executions:

class TestDLLDump(testlib.HashChecker):
    PARAMETERS = dict(
        commandline="dlldump --pid %(pid)s --dump-dir %(tempdir)s",
        )

Since the pid is likely to change between images, the user is required to
customized the precise pid to test for in the test configuation file:

[TestDLLDump]
pid = 2536

"""

__author__ = "Michael Cohen <scudette@gmail.com>"

import argparse
import logging
import json
import subprocess
import multiprocessing
import os
import shutil
import sys
import tempfile
import threading
import time
import yaml
import unittest

from rekall import config as rekall_config
from rekall import plugin
from rekall import session
from rekall import utils
from rekall import testlib
from rekall import threadpool
from rekall.ui import text

# Bring in all the tests and all the plugins
# pylint: disable=unused-import
from rekall import plugins
from rekall import tests
# pylint: enable=unused-import


NUMBER_OF_CORES = multiprocessing.cpu_count()


class RekallTester(object):
    """A class to manage running and controlling the test harness."""

    BASELINE_TEMPLATE = """#!/bin/bash
if [ "$1" == "ok" ]; then
   cp %(src)s %(dest)s
elif [ "$1" == "meld" ]; then
   meld %(src)s %(dest)s
elif [ "$1" == "diff" ]; then
   diff %(src)s %(dest)s
elif [ "$1" == "run" ]; then
   %(command)s
else
   less %(src)s
fi
exit 0
"""

    def __init__(self, argv=None, renderer=None):
        self.FLAGS = self.ProcessCommandLineArgs(argv)
        self.threadpool = threadpool.ThreadPool(self.FLAGS.processes)

        # The path that contains all the baselines.
        self.test_directory = os.path.dirname(
            os.path.abspath(self.FLAGS.config))

        # The path that we write all files to.
        self.output_dir = os.path.join(
            self.test_directory, self.FLAGS.output_dir)

        self.EnsureDirExists(self.output_dir)

        if self.FLAGS.verbose:
            logging.getLogger().setLevel(logging.DEBUG)

        self.renderer = renderer

        # Some stats.
        self.successes = []
        self.failures = []
        self.rebuilt = 0

    def EnsureDirExists(self, dirname):
        try:
            os.makedirs(dirname)
        except OSError:
            pass

    def ProcessCommandLineArgs(self, argv=None):
        parser = argparse.ArgumentParser()

        parser.add_argument("--processes", default=NUMBER_OF_CORES, type=int,
                            help="Number of concurrent workers.")

        parser.add_argument("-v", "--verbose", default=False,
                            action="store_true",
                            help="Output verbosity.")

        parser.add_argument("-e", "--executable",
                            default="rekall ",
                            help="The path to the rekall binary.")

        parser.add_argument("-c", "--config", default="tests.config",
                            help="Filename for the main test config file.")

        parser.add_argument("-d", "--debug", default=False,
                            action="store_true",
                            help="Turn on test debugging.")

        parser.add_argument("--output_dir", default="output",
                            help="Create all files inside this directory.")

        parser.add_argument("-b", "--baseline", default=False,
                            action="store_true",
                            help="If specified rebuild the baseline instead of "
                            "testing against it.")

        parser.add_argument("-i", "--inline", default=False,
                            action="store_true",
                            help="If specified, output failures inline.")

        parser.add_argument("tests", nargs="*", help="Tests to run")

        return parser.parse_args(args=argv)

    def LoadConfigFile(self):
        """Parses the the config file.

        Applies interpolations and produces a dict of config options for each
        test. This also adds useful defaults to be available for interpolations
        in the config file itself. This config file is not written back.

        Returns:
          a dict with keys being the test names, and values being config_options
          for each test.
        """
        config = yaml.load(open(self.FLAGS.config).read())

        # Set some useful defaults - These do not get written to the file.
        config.setdefault("DEFAULT", {})
        defaults = config["DEFAULT"]
        defaults.update(dict(
            tempdir=self.temp_directory,
            testdir=self.test_directory,
            executable=self.FLAGS.executable))

        # Extra options to be used for testing.
        defaults["--renderer"] = "test"


        for test_config in config.values():
            # For each test config interpolate the parameter if it is a string.
            for k, v in test_config.items():
                merged_config = defaults.copy()
                merged_config.update(test_config)

                if isinstance(v, basestring):
                    v = v % merged_config
                    test_config[k] = v

        return utils.AttributeDict(config)

    def BuildBaselineData(self, config_options, plugin_cls):
        # Operate on a copy here as we need to provide this test a unique
        # tempdir to write on.
        config_options = config_options.copy()

        config_options["tempdir"] = os.path.join(
            config_options["tempdir"],
            plugin_cls.__name__ + threading.current_thread().getName())

        # This directory should not exist already!
        os.mkdir(config_options["tempdir"])

        plugin_obj = plugin_cls(temp_directory=config_options["tempdir"])
        start = time.time()

        baseline_data = plugin_obj.BuildBaselineData(config_options)
        if baseline_data is None:
            baseline_data = {}

        baseline_data["options"] = config_options
        baseline_data["time_used"] = time.time() - start

        return baseline_data

    def BuildBaselineTask(self, config_options, plugin_cls):
        """Run the rekall test program.

        This runs in a separate thread on the thread pool. After
        running, we capture the output into a json baseline file, and
        print progress to the terminal.
        """
        baseline_data = self.BuildBaselineData(config_options, plugin_cls)

        output_filename = os.path.join(self.test_directory, plugin_cls.__name__)

        with open(output_filename, "wb") as baseline_fd:
            baseline_fd.write(json.dumps(baseline_data, indent=4))
            self.renderer.table_row(
                plugin_cls.__name__,
                utils.AttributedString("REBUILD", [(0, -1, "YELLOW", None)]),
                baseline_data["time_used"])

            self.rebuilt += 1

    def __enter__(self):
        self.temp_directory = tempfile.mkdtemp()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Manage proper cleanup of threads and files."""
        # This will block until all the threads are done.
        self.threadpool.Stop()
        shutil.rmtree(self.temp_directory, True)

        # Write the json summary of the results.
        with open(os.path.join(self.output_dir, "results"), "wb") as fd:
            json.dump(dict(passes=self.successes, fails=self.failures), fd)

    def GenerateTests(self, config):
        """Generates test classes for all the plugins.

        Each plugin must have at least one test. Plugin tests are subclasses of
        the testlib.RekallBaseUnitTestCase class,
        """
        result = []

        # Pull the profile path etc from the rekall config file.
        kwargs = rekall_config.GetConfigFile()

        # Get the disabled tests.
        disabled = config.pop("disabled", [])

        for x, y in config.items():
            if x.startswith("--"):
                kwargs[x[2:]] = y

        s = session.InteractiveSession(**kwargs)

        # A map of all the specialized tests which are defined. Only include
        # those classes which are active for the currently selected profile.
        plugins_with_test = set()
        for _, cls in testlib.RekallBaseUnitTestCase.classes.items():
            if cls.is_active(s):
                result.append(cls)

                plugin_name = cls.CommandName()
                if plugin_name:
                    plugins_with_test.add(plugin_name)

        # Now generate tests automatically for all other plugins.
        for cls in plugin.Command.classes.values():
            if cls.name in plugins_with_test:
                continue

            # We can not test interactive plugins in this way.
            if cls.interactive:
                continue

            # Remove classes which are not active.
            if not cls.is_active(s):
                continue

            # Automatically create a new test based on testlib.SimpleTestCase.
            try:
                result.append(type(
                    "Test%s" % cls.__name__, (testlib.SimpleTestCase,),
                    dict(PARAMETERS=dict(commandline=cls.name))))
            except RuntimeError:
                pass

        # Remove the disabled tests.
        return [x for x in result if x.__name__ not in disabled]

    def RunTests(self):
        if not os.access(self.FLAGS.config, os.R_OK):
            logging.error("Config file %s not found.", self.FLAGS.config)
            sys.exit(-1)

        logging.info("Testing baselines for config file %s", self.FLAGS.config)

        config = self.LoadConfigFile()

        # Use the options in the DEFAULT section to select the plugins which
        # apply to this profile.
        config_options = config.DEFAULT
        if self.FLAGS.verbose:
            config_options["--verbose"] = True

        self.renderer.table_header([("Test", "test", "60"),
                                    ("Status", "status", "15"),
                                    ("Time", "time", "20"),
                                    ("Expected Time", "expected", "20"),
                                    ("Error File", "error", "")])

        for plugin_cls in self.GenerateTests(config_options):
            # Allow the user to specify only some tests to run.
            if self.FLAGS.tests and plugin_cls.__name__ not in self.FLAGS.tests:
                continue

            if plugin_cls.disabled:
                continue

            # Retrieve the configured options if they exist.
            config_options = plugin_cls.PARAMETERS.copy()

            # Defaults section overrides the PARAMETERS attribute.
            config_options.update(config.DEFAULT)

            config_options["test_class"] = plugin_cls.__name__

            if plugin_cls.__name__ in config:
                config_options.update(config.Get(plugin_cls.__name__))

            # Try to get the previous baseline file.
            baseline_filename = os.path.join(
                self.test_directory, plugin_cls.__name__)

            try:
                data = open(baseline_filename, "rb").read()
                # Strip possible preamble:
                data = data[data.find("{"):]
                baseline_data = json.loads(data)
            except Exception:
                baseline_data = None

            # Should we build the baseline or test against it?
            if baseline_data is None or self.FLAGS.baseline:
                logging.info("Rebuilding baseline file %s.",
                             plugin_cls.__name__)

                # process == 0 means we run tests in series.
                if self.FLAGS.processes == 0:
                    self.BuildBaselineTask(config_options, plugin_cls)
                else:
                    self.threadpool.AddTask(self.BuildBaselineTask, [
                        config_options, plugin_cls])

            else:
                # process == 0 means we run tests in series.
                if self.FLAGS.processes == 0:
                    self.RunTestCase(config_options, plugin_cls, baseline_data)
                else:
                    self.threadpool.AddTask(self.RunTestCase, [
                        config_options, plugin_cls, baseline_data])

    def RunTestCase(self, config_options, plugin_cls, baseline_data):
        if baseline_data['options'].get('aborted'):
            logging.info("Skipping test %s since baseline did not complete.",
                         plugin_cls.__name__)
            return

        # Re-Run the current test again.
        current_run = self.BuildBaselineData(config_options, plugin_cls)

        test_cases = []
        for name in dir(plugin_cls):
            if name.startswith("test"):
                test_cases.append(
                    plugin_cls(
                        name, baseline=baseline_data,
                        config_options=config_options,
                        current=current_run, debug=self.FLAGS.debug))

        for test_case in test_cases:
            result = unittest.TestResult()
            return_code = current_run.get("return_code", 0)
            if return_code != 0:
                result.errors.append(("return_code", return_code))

            test_case(result)

            current_run["errors"] = dict(
                (str(x), y) for x, y in result.errors)

            current_run["failures"] = dict(
                (str(x), y) for x, y in result.failures)

            # Store the current run someplace for closer inspection.
            output_path = os.path.join(self.output_dir, plugin_cls.__name__)
            with open(output_path, "wb") as fd:
                baseline_filename = os.path.join(
                    self.test_directory, plugin_cls.__name__)

                fd.write(self.BASELINE_TEMPLATE % dict(
                    src=fd.name, dest=baseline_filename,
                    command=current_run["options"].get(
                        "executed_command", "echo hello")))

                fd.write(json.dumps(current_run, indent=4))

            # Make the output executable.
            os.chmod(output_path, 0770)

            if result.wasSuccessful():
                self.renderer.table_row(
                    test_case,
                    utils.AttributedString("PASS", [(0, -1, "GREEN", None)]),
                    current_run.get("time_used", 0),
                    baseline_data.get("time_used", 0))
                self.successes.append(plugin_cls.__name__)

            else:
                diff_path = output_path + ".diff"
                with open(diff_path, "wb") as diff_fd:
                    subprocess.call(
                        ["diff", "-y", "--width", "200",
                         output_path, baseline_filename],
                        stdout=diff_fd)

                if self.FLAGS.inline:
                    print open(output_path).read()

                self.renderer.table_row(
                    test_case,
                    utils.AttributedString("FAIL", [(0, -1, "RED", None)]),
                    current_run.get("time_used", 0),
                    baseline_data.get("time_used", 0),
                    fd.name)

                self.failures.append(plugin_cls.__name__)

                if self.FLAGS.verbose:
                    for test_case, error in result.errors + result.failures:
                        self.renderer.write("Error in %s: %s" % (
                            plugin_cls.__name__, error))


def main(_):
    start = time.time()
    # We dont want a pager for the main view.
    user_session = session.InteractiveSession(pager="-")
    renderer = text.TextRenderer(session=user_session)
    with renderer.start():
        with RekallTester(renderer=renderer) as tester:
            tester.RunTests()

    tester.renderer.write(
        "Completed %s tests (%s passed, %s failed, %s rebuild) in "
        "%s Seconds.\n" % (len(tester.successes) + len(tester.failures),
                           len(tester.successes), len(tester.failures),
                           tester.rebuilt, int(time.time() - start)))

    # Return an error when any tests failed.
    if tester.failures:
        sys.exit(-1)


if __name__ == "__main__":
    main(sys.argv)
