#!/usr/bin/env python2

# Rekall Memory Forensics
# Copyright 2015 Google Inc. All Rights Reserved.
#
# Author: Michael Cohen scudette@google.com
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

__author__ = "Michael Cohen <scudette@google.com>"

"""A plugin to install relevant kernel modules to enable live analysis.

The intention is to allow the user to launch:

rekall live

and have Rekall install the right kernel module and connect to the driver on all
supported operating systems.
"""
import os
import platform
import re
import win32service

from rekall import resources
from rekall import plugin
from rekall import obj
from rekall.plugins.addrspaces import win32


class Live(plugin.TypedProfileCommand,
           plugin.ProfileCommand):
    """Launch a Rekall shell for live analysis on the current system."""

    name = "live"

    PROFILE_REQUIRED = False

    __args = [
        dict(name="driver",
             help="Driver file to load"),

        dict(name="device", default=r"\\.\pmem",
             help="Device name to use"),

        dict(name="service_name", default=r"pmem",
             help="Service name to use")
    ]

    table_header = [
        dict(name="Message")
    ]

    def __init__(self, *args, **kw):
        super(Live, self).__init__(*args, **kw)
        # It is OK for non privileged sessions to use the default drivers.
        if not self.session.privileged and self.plugin_args.driver:
            raise plugin.PluginError(
                "Installing arbitrary drivers is only available for "
                "interactive or privileged sessions.")

        # Did we start the service? If so we need to clean up.
        self.we_started_service = False
        self.hScm = None
        self.hSvc = None

    exception_format_regex = re.compile(r": \((\d+),")
    def parse_exception(self, e):
        """Yes! seriously there is no way to get at the real error code."""
        # We often see code like if "Access Denied" in str(e):... but
        # this is unreliable since the message will be different when
        # different language packs are used. The best way is to
        # compare the numeric error code, but this is not exported. In
        # our testing e.errno is not being set properly by pywin32.
        m = self.exception_format_regex.search(str(e))
        if m:
            return int(m.group(1))

    def load_driver(self):
        """Load the driver if possible."""
        # Check the driver is somewhere accessible.
        if self.plugin_args.driver is None:
            # Valid values
            # http://superuser.com/questions/305901/possible-values-of-processor-architecture
            machine = platform.machine()
            if machine == "AMD64":
                driver = "winpmem_x64.sys"
            elif machine == "x86":
                driver = "winpmem_x86.sys"
            else:
                raise plugin.PluginError("Unsupported architecture")

            self.plugin_args.driver = resources.get_resource(
                "WinPmem/%s" % driver)

            # Try the local directory
            if self.plugin_args.driver is None:
                self.plugin_args.driver = os.path.join(
                    os.getcwd(), "WinPmem", driver)

        self.session.logging.debug("Loading driver from %s",
                                   self.plugin_args.driver)

        if not os.access(self.plugin_args.driver, os.R_OK):
            raise plugin.PluginError(
                "Driver file %s is not accessible." % self.plugin_args.driver)

        self.hScm = win32service.OpenSCManager(
            None, None, win32service.SC_MANAGER_CREATE_SERVICE)

        # First uninstall the driver
        self.remove_service(also_close_as=False)

        try:
            self.hSvc = win32service.CreateService(
                self.hScm, self.plugin_args.service_name,
                self.plugin_args.service_name,
                win32service.SERVICE_ALL_ACCESS,
                win32service.SERVICE_KERNEL_DRIVER,
                win32service.SERVICE_DEMAND_START,
                win32service.SERVICE_ERROR_IGNORE,
                self.plugin_args.driver,
                None, 0, None, None, None)

            self.session.logging.debug("Created service %s",
                                       self.plugin_args.service_name)
            # Remember to cleanup afterwards.
            self.we_started_service = True

        except win32service.error as e:
            # Service is already there, try to open it instead.
            self.hSvc = win32service.OpenService(
                self.hScm, self.plugin_args.service_name,
                win32service.SERVICE_ALL_ACCESS)

        # Make sure the service is stopped.
        try:
            win32service.ControlService(
                self.hSvc, win32service.SERVICE_CONTROL_STOP)
        except win32service.error:
            pass

        try:
            win32service.StartService(self.hSvc, [])
        except win32service.error, e:
            self.session.logging.debug("%s: will try to continue", e)

        try:
            return win32.WinPmemAddressSpace(
                session=self.session, filename=self.plugin_args.device)
        except IOError as e:
            raise plugin.PluginError(*e.args)

    def live(self):
        phys_as = obj.NoneObject("Unable to access physical memory")
        try:
            phys_as = win32.WinPmemAddressSpace(
                session=self.session, filename=self.plugin_args.device)
        except IOError as e:
            self.session.logging.debug("%s", e)
            errno = self.parse_exception(e)
            if errno == 5:   # Access Denied.
                self.session.logging.error(
                    "%s. Are you running as Administrator?" % e)

            elif errno == 2: # File not found
                try:
                    phys_as = self.load_driver()
                except plugin.PluginError:
                    self.session.logging.error(
                        "Unable to load driver: %s." % e)

            else:
                self.session.logging.error(
                    "Unable to access physical memory: %s." % e)

        self.session.physical_address_space = phys_as
        self.session.GetParameter("live", True)

    def remove_service(self, also_close_as=True):
        self.session.logging.debug("Removing service %s",
                                   self.plugin_args.service_name)

        # Make sure the handle is closed.
        if also_close_as:
            self.session.physical_address_space.close()

        # Stop the service if it's running.
        if not self.hSvc:
            try:
                self.hSvc = win32service.OpenService(
                    self.hScm, self.plugin_args.service_name,
                    win32service.SERVICE_ALL_ACCESS)
            except win32service.error:
                self.session.logging.debug("%s service does not exist.",
                                           self.plugin_args.service_name)

        if self.hSvc:
            self.session.logging.debug("Stopping service: %s",
                                       self.plugin_args.service_name)
            try:
                win32service.ControlService(
                    self.hSvc, win32service.SERVICE_CONTROL_STOP)
            except win32service.error as e:
                self.session.logging.debug("Error stopping service: %s", e)

            self.session.logging.debug("Deleting service: %s",
                                       self.plugin_args.service_name)
            try:
                win32service.DeleteService(self.hSvc)
            except win32service.error as e:
                self.session.logging.debug("Error deleting service: %s", e)

            win32service.CloseServiceHandle(self.hSvc)

    def close(self):
        if self.we_started_service:
            self.remove_service()

    def __enter__(self):
        self.live()
        return self

    def __exit__(self, exc_type, exc_value, trace):
        self.close()

    def collect(self):
        yield ("Launching live memory analysis\n",)
        try:
            self.live()

            renderer = self.session.GetRenderer()

            # Launch the shell.
            shell = self.session.plugins.shell()
            shell.render(renderer)
        finally:
            self.close()
