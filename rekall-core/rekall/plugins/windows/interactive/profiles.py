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
from rekall import addrspace
from rekall import plugin
from rekall.plugins.overlays.windows import pe_vtypes

from rekall.plugins.windows import common


class LoadWindowsProfile(common.AbstractWindowsCommandPlugin):
    """Loads the profile into the session.

    If the profile does not exist in the repositories, fetch and build it from
    the symbol server. This plugin allows the user to change resolution of
    selected binaries by forcing the fetching of symbol files from the symbol
    server interactively.
    """

    name = "load_profile"

    interactive = True

    @classmethod
    def args(cls, parser):
        super(LoadWindowsProfile, cls).args(parser)
        parser.add_argument(
            "module_name",
            help="The name of the module (without the .pdb extensilon).",
            required=True)

        parser.add_argument(
            "guid", help="The guid of the module.",
            required=False)

    def __init__(self, module_name=None, guid=None, **kwargs):
        super(LoadWindowsProfile, self).__init__(**kwargs)
        self.module_name = module_name
        self.guid = guid

    def render(self, renderer):
        if self.guid is None:
            # Try to detect the GUID automatically.
            module = self.session.address_resolver.GetModuleByName(
                self.module_name)
            if not module:
                raise plugin.PluginError(
                    "Unknown module %s." % self.module_name)

            profile_name = module.detect_profile_name()
            if not profile_name:
                raise plugin.PluginError(
                    "Unable to determine GUID for module %s." %
                    self.module_name)
        else:
            profile_name = "%s/GUID/%s" % (self.module_name, self.guid)

        profile = self.session.LoadProfile(profile_name)
        if profile == None:
            # Try to build it from the symbol serv
            profile = module.build_local_profile(profile_name, force=True)
            if profile == None:
                raise plugin.PluginError(
                    "Unable to fetch or build %s" % profile_name)

        if profile:
            module.profile = profile
