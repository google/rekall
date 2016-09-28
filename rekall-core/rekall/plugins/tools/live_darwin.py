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
import subprocess
import tarfile

from rekall import plugin
from rekall import obj
from rekall import resources
from rekall import session
from rekall import utils

from rekall.plugins.addrspaces import pmem


class Live(plugin.TypedProfileCommand,
           plugin.ProfileCommand):
    """Launch a Rekall shell for live analysis on the current system."""

    name = "live"

    PROFILE_REQUIRED = False

    __args = [
        dict(name="mode", default="Memory", type="Choices",
             choices=session.LIVE_MODES,
             help="Mode for live analysis."),

        dict(name="driver_path",
             help="Driver file to load"),

        dict(name="device", default=r"/dev/pmem",
                            help="Device name to use"),

        dict(name="unload", type="Boolean",
             help="Just unload the driver and exit."),

        dict(name="load", type="Boolean",
             help="Just load the driver and exit."),
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

        self.driver_path = (self.plugin_args.driver_path or
                            resources.get_resource("MacPmem.kext.tgz"))
        if self.driver_path is None:
            raise IOError("Driver resource not found.")

        # Did we load the driver? If so we need to clean up.
        self.we_started_driver = False

    def load_driver(self):
        """Unpack and load the driver."""
        tarfile_handle = tarfile.open(self.plugin_args.driver_path)

        # Try to extract the resource into a tempdir.
        with utils.TempDirectory() as tmp_name:
            self.session.logging.info("Unpacking driver to %s", tmp_name)
            tarfile_handle.extractall(tmp_name)

            # Change ownership of the extracted files to make sure they are
            # owned by root otherwise they will not load.
            for root, files, dirs in os.walk(tmp_name):
                for f in files:
                    os.chown(os.path.join(root, f), 0, 0)

                for d in dirs:
                    os.chown(os.path.join(root, d), 0, 0)

            for member_name in tarfile_handle.getnames():
                if member_name.endswith(".kext"):
                    self.member_name = member_name.lstrip("/")
                    full_driver_path = os.path.join(tmp_name,
                                                    self.member_name)
                    self.session.logging.info(
                        "Loading driver from %s", full_driver_path)
                    res = subprocess.check_call(
                        ["kextload", full_driver_path])

                    if res != 0:
                        raise plugin.PluginError(
                            "Failed to load driver. Are you root?")

    def live(self):
        phys_as = obj.NoneObject("Unable to access physical memory")

        if self.plugin_args.mode == "Memory":
            try:
                phys_as = pmem.MacPmemAddressSpace(
                    session=self.session,
                    filename=self.plugin_args.device)
            except IOError as e:
                self.session.logging.debug("%s", e)
                self.load_driver()
                phys_as = pmem.MacPmemAddressSpace(
                    session=self.session,
                    filename=self.plugin_args.device)

        self.session.physical_address_space = phys_as
        with self.session:
            self.session.SetParameter("live_mode", self.plugin_args.mode)
            self.session.SetParameter("session_name", "Live (%s)" %
                                      self.plugin_args.mode)

    def unload_driver(self):
        tarfile_handle = tarfile.open(self.plugin_args.driver_path)

        for member_name in tarfile_handle.getnames():
            if not member_name.endswith(".kext"):
                continue

            self.member_name = member_name.lstrip("/")

            # Try to extract the resource into a tempdir.
            with utils.TempDirectory() as tmp_name:
                tarfile_handle.extractall(tmp_name)
                full_driver_path = os.path.join(tmp_name,
                                                self.member_name)
                self.session.logging.info(
                    "Unloading driver from %s", full_driver_path)
                try:
                    subprocess.check_call(
                        ["kextunload",
                         os.path.join(tmp_name, self.member_name)])
                except Exception as e:
                    # There isnt much we can do about it here.
                    self.session.logging.debug(
                        "Unable to unload driver: %s" % e)

    def close(self):
        if self.we_started_driver:
            self.unload_driver()

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

    def __enter__(self):
        self.live()
        return self

    def __exit__(self, exc_type, exc_value, trace):
        self.close()
