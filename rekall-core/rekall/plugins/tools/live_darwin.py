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
import rekall

from rekall import plugin
from rekall import utils

from rekall.plugins.addrspaces import pmem


class Live(plugin.PrivilegedMixIn, plugin.ProfileCommand):
    """Launch a Rekall shell for live analysis on the current system."""

    name = "live"

    PROFILE_REQUIRED = False

    @classmethod
    def args(cls, parser):
        parser.add_argument("--driver_path", default=None,
                            help="Driver file to load")

        parser.add_argument("--device", default=r"/dev/pmem",
                            help="Device name to use")

        parser.add_argument("-u", "--unload", default=None, type="Boolean",
                            help="Just unload the driver and exit.")

        parser.add_argument("-l", "--load", default=None, type="Boolean",
                            help="Just load the driver and exit.")

    def __init__(self, driver_path=None, device=r"/dev/pmem", unload=None,
                 load=None, **kw):
        super(Live, self).__init__(**kw)
        self.driver_path = driver_path
        if self.driver_path is None:
            self.driver_path = os.path.join(rekall.RESOURCES_PATH,
                                            "MacPmem.kext.tgz")
        self.device = device
        self.unload = unload
        self.load = load

        # Did we load the driver? If so we need to clean up.
        self.we_started_driver = False

    def live(self):
        try:
            base_as = pmem.MacPmemAddressSpace(session=self.session,
                                               filename=self.device)
        except IOError as e:
            self.session.logging.debug("%s", e)
            tarfile_handle = tarfile.open(self.driver_path)

            # Try to extract the resource into a tempdir.
            with utils.TempDirectory() as tmp_name:
                self.session.logging.info("Unpacking driver to %s", tmp_name)
                tarfile_handle.extractall(tmp_name)

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
                            raise plugin.PluginError("%s. Are you root?" % e)

                        try:
                            base_as = pmem.MacPmemAddressSpace(session=self.session,
                                                               filename=self.device)
                            self.we_started_driver = True
                            break
                        except IOError as e:
                            self.session.logging.debug("%s", e)
                            raise plugin.PluginError("%s. Are you root?" % e)

        self.session.physical_address_space = base_as

    def close(self):
        if self.unload or self.we_started_driver:
            tarfile_handle = tarfile.open(self.driver_path)

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
                    res = subprocess.check_call(
                        ["kextunload", os.path.join(tmp_name, self.member_name)])
                    if res != 0:
                        raise plugin.PluginError("Unable to unload driver: %s" % e)

    def render(self, renderer):
        renderer.format("Launching live memory analysis\n")
        if self.unload:
            return self.close()

        if self.load:
            # Live the driver loaded.
            return self.live()

        try:
            self.live()

            # Launch the shell.
            shell = self.session.plugins.shell()
            shell.render(renderer)
        finally:
            self.close()
