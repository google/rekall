# Volatility
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
"""

import argparse
import ConfigParser
import logging
import json
import os
import Queue
import re
import shutil
import subprocess
import sys
import tempfile
import time
import threading
import traceback
import unittest

from volatility import testlib
from volatility.ui import renderer

# Bring in all the tests
from volatility.plugins import tests


# Simple threadpool implementation - we just run all tests in the pool for
# maximum concurrency.
class Worker(threading.Thread):
    """A Threadpool worker.

    Reads jobs from the queue and runs them. Quits when a None job is received
    on the queue.
    """
    def __init__(self, queue):
        super(Worker, self).__init__()
        self.queue = queue
        self.daemon = True

        # Start the thread immediately.
        self.start()

    def run(self):
        while True:
            # Great a callable from the queue.
            task, args = self.queue.get()

            try:
                # Stop the worker by sending it a task of None.
                if task is None:
                    break

                task(*args)
            except Exception, e:
                logging.error("Worker raised %s", e)
                traceback.print_exc()

            finally:
                self.queue.task_done()


class ThreadPool(object):
    lock = threading.Lock()

    def __init__(self, number_of_threads):
        self.number_of_threads = number_of_threads
        self.queue = Queue.Queue(2 * number_of_threads)
        self.workers = [Worker(self.queue) for _ in range(number_of_threads)]

    def Stop(self):
        """Stop all the threads when they are ready."""
        # Send all workers the stop message.
        for worker in self.workers:
            self.AddTask(None)

        self.queue.join()
        for worker in self.workers:
            worker.join()

    def AddTask(self, task, args=None):
        self.queue.put((task, args or []))


class VolatilityTester(object):
    """A class to manage running and controlling the test harness."""

    def __init__(self, argv=None):
        self.FLAGS = self.ProcessCommandLineArgs(argv)
        self.threadpool = ThreadPool(self.FLAGS.processes)
        self.test_directory = os.path.dirname(self.FLAGS.config)
        if self.FLAGS.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
        self.renderer = renderer.TextRenderer()

    def ProcessCommandLineArgs(self, argv=None):
        parser = argparse.ArgumentParser()

        parser.add_argument("--processes", default=5, type=int,
                            help="Number of concurrent workers.")

        parser.add_argument("-v", "--verbose", default=False,
                            action="store_true",
                            help="Number of concurrent workers.")

        subparsers = parser.add_subparsers(
                            description="Action to execute",
                            metavar="action")

        template_parser = subparsers.add_parser(
            "template",
            help="Build an initial template for a test suite")

        template_parser.add_argument(
            "-f", "--filename", help="The filename of the tested image.")

        template_parser.add_argument(
            "-p", "--profile", default="WinXPSP2x86",
            help="The profile to use.")

        template_parser.add_argument(
            "-c", "--config", default="tests.config",
            help="Filename for the main test config file.")

        template_parser.add_argument(
            "--active", default=False, action="store_true",
            help="If set, by default, template plugins will be active")

        template_parser.add_argument("tests", nargs="*",
                                     help="Create baseline for these tests.")

        template_parser.set_defaults(action="template")


        baseline_parser = subparsers.add_parser(
            "baseline", help="Build a baseline using the config file.")

        baseline_parser.set_defaults(action="baseline")

        baseline_parser.add_argument("-c", "--config", default="tests.config",
                                     help="Filename for the main test config "
                                     "file.")

        baseline_parser.add_argument("-e", "--executable",
                                     default="python vol.py ",
                                     help="The path to the volatility binary.")

        baseline_parser.add_argument(
            "--mode", default="ng", choices=["ng", "trunk"],
            help="The type of executable this is.")

        baseline_parser.add_argument("tests", nargs="*",
                                     help="Create baseline for these tests.")

        test_parser = subparsers.add_parser(
            "test", help="Run the tests and compare with the baseline file.")

        test_parser.add_argument("-c", "--config", default="tests.config",
                                 help="Filename for the main test config file.")

        test_parser.add_argument("-e", "--executable", default="python vol.py ",
                                 help="The path to the volatility binary.")

        test_parser.add_argument(
            "--mode", default="ng", choices=["ng", "trunk"],
            help="The type of executable this is.")

        test_parser.add_argument("-d", "--debug", default=False,
                                 action="store_true",
                                 help="Turn on test debugging.")

        test_parser.add_argument("tests", nargs="*", help="Tests to run")

        test_parser.set_defaults(action="test")

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
        config = ConfigParser.SafeConfigParser()
        config.read(self.FLAGS.config)

        # Set some useful defaults - These do not get written to the file.
        config.set(None, "tempdir", self.temp_directory)
        config.set(None, "executable", self.FLAGS.executable)

        # Modify the filename parameter to include the test directory. Note
        # that if the config file specifies the image's fully qualified path
        # (i.e. starts with /) this will still point to the correct path.
        config.set(None, "filename", os.path.join(
                    self.test_directory, config.get("DEFAULT", "filename")))

        # Extra options to be used for testing the tech preview branch.
        if self.FLAGS.mode == "ng":
            config.set(None, "--renderer", "TestRenderer")

        return config

    def MakeTemplate(self):
        """Builds a template for a test suite."""
        if not os.access(self.FLAGS.filename, os.R_OK):
            raise RuntimeError("Filename %s does not appear to be a file." %
                               self.FLAGS.filename)

        image_filename = os.path.basename(self.FLAGS.filename)

        config = ConfigParser.SafeConfigParser()

        config_filename = os.path.join(
            os.path.dirname(self.FLAGS.filename), self.FLAGS.config)

        config.read(config_filename)

        # Add default parameters.
        config.set(None, "filename", image_filename)
        config.set(None, "profile", self.FLAGS.profile)

        # Make all plugins active by default - this way they can easily be
        # enabled by removing the active = False line in each test's section.
        config.set(None, "active", "True")

        for case, case_cls in testlib.VolatilityBaseUnitTestCase.classes.items():
            # Allow the user to specify only some tests to run.
            if self.FLAGS.tests and case not in self.FLAGS.tests:
                continue

            config.remove_section(case)
            config.add_section(case)

            # Set up some sensible defaults for each test - these will be
            # interpolated from the default section.
            test_parameters = {
                # By default take filename and profile from the default section.
                "--filename": "%(filename)s",
                "--profile": "%(profile)s",

                # By default all tests are inactive.
                "active": str(self.FLAGS.active)}

            # Allow the test class to set default values for parameters.
            test_parameters.update(case_cls.PARAMETERS)

            for k, v in test_parameters.items():
                config.set(case, k, str(v))

            with open(config_filename, 'wb') as configfile:
                config.write(configfile)

    def BuildBaseLine(self):
        config = self.LoadConfigFile()

        self.renderer.table_header([("Test", "test", "<30s"),
                                    ("Time", "time", "0.2f")])

        for plugin in config.sections():
            # Allow the user to specify only some tests to run.
            if self.FLAGS.tests and plugin not in self.FLAGS.tests:
                continue

            plugin_cls = testlib.VolatilityBaseUnitTestCase.classes.get(plugin)
            if plugin_cls is None:
                logging.error("Unknwon test name in config file: %s", plugin)
                continue

            config_options = dict(config.items(plugin))
            config_options["mode"] = self.FLAGS.mode

            if not config.getboolean(plugin, "active"):
                logging.info("Skipping plugin %s since its disabled.", plugin)
                continue

            # process == 0 means we run tests in series.
            if self.FLAGS.processes == 0:
                self.BuildBaseLineTask(config_options, plugin_cls)
            else:
                self.threadpool.AddTask(self.BuildBaseLineTask, [
                        config_options, plugin_cls])

    def BuildBaseLineTask(self, config_options, plugin_cls):
        """Run the volatility test program.

        This runs in a separate thread on the thread pool. After
        running, we capture the output into a json baseline file, and
        print progress to the terminal.
        """
        plugin = plugin_cls(temp_directory=self.temp_directory,
                            running_mode=self.FLAGS.mode)
        start = time.time()

        baseline_data = plugin.BuildBaseLineData(config_options)
        if baseline_data is None:
            baseline_data = {}

        baseline_data["options"] = config_options
        baseline_data["time_used"] = time.time() - start

        output_filename = os.path.join(self.test_directory, plugin_cls.__name__)

        with open(output_filename, "wb") as baseline_fd:
            baseline_fd.write(json.dumps(baseline_data, indent=4))
            self.renderer.table_row(plugin_cls.__name__,
                                    baseline_data["time_used"])

    def __enter__(self):
        self.temp_directory = tempfile.mkdtemp()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Manage proper cleanup of threads and files."""
        # This will block until all the threads are done.
        self.threadpool.Stop()
        shutil.rmtree(self.temp_directory, True)

    def RunTests(self):
        config = self.LoadConfigFile()

        self.renderer.table_header([("Test", "test", "<30s"),
                                    ("Status", "status", "^10s"),
                                    ("Time", "time", "^0.2f"),
                                    ("Expected Time", "expected", "^0.2f")])

        for plugin in config.sections():
            # Allow the user to specify only some tests to run.
            if self.FLAGS.tests and plugin not in self.FLAGS.tests:
                continue

            plugin_cls = testlib.VolatilityBaseUnitTestCase.classes.get(plugin)
            if plugin_cls is None:
                logging.error("Unknwon test name in config file: %s", plugin)
                continue

            config_options = dict(config.items(plugin))

            baseline_filename = os.path.join(self.test_directory, plugin)
            try:
                baseline_data = json.load(open(baseline_filename, "rb"))
            except IOError:
                continue

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
        start = time.time()
        plugin = plugin_cls(temp_directory=self.temp_directory,
                            running_mode=self.FLAGS.mode,
                            baseline=baseline_data)
        current_run = plugin.BuildBaseLineData(config_options)

        time_taken = time.time() - start

        test_cases = []
        for name in dir(plugin_cls):
            if name.startswith("test"):
                test_cases.append(
                    plugin_cls(name, baseline=baseline_data,
                               current=current_run, debug=self.FLAGS.debug))

        for test_case in test_cases:
            result = unittest.TestResult()
            test_case(result)

            if result.wasSuccessful():
                self.renderer.table_row(
                    plugin_cls.__name__,
                    self.renderer.color("PASS", foreground="GREEN"),
                    time_taken, baseline_data.get("time_used", 0))
            else:
                self.renderer.table_row(
                    plugin_cls.__name__,
                    self.renderer.color("FAIL", foreground="RED"),
                    time_taken, baseline_data.get("time_used", 0))

                if self.FLAGS.verbose:
                    for test_case, error in result.errors + result.failures:
                        self.renderer.write("Error in %s: %s" % (
                                plugin_cls.__name__, error))

    def ParseCommandLineArgs(self):
        if self.FLAGS.action == "template":
            if self.FLAGS.filename is None:
                logging.error("No image filename specified.")
                sys.exit(-1)

            logging.info("Creating template for image %s", self.FLAGS.filename)
            self.MakeTemplate()

        elif self.FLAGS.action == "baseline":
            if not os.access(self.FLAGS.config, os.R_OK):
                logging.error("Config file %s not found.", self.FLAGS.config)
                sys.exit(-1)

            logging.info("Building baselines for config file %s", self.FLAGS.config)
            self.BuildBaseLine()
        elif self.FLAGS.action == "test":
            if not os.access(self.FLAGS.config, os.R_OK):
                logging.error("Config file %s not found.", self.FLAGS.config)
                sys.exit(-1)

            logging.info("Testing baselines for config file %s", self.FLAGS.config)
            self.RunTests()


def main(argv):
    with VolatilityTester() as tester:
        tester.ParseCommandLineArgs()


if __name__ == "__main__":
    main(sys.argv)
