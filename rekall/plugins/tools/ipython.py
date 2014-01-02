#!/usr/bin/env python2

# Rekall Memory Forensics
# Copyright 2013 Google Inc. All Rights Reserved.
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
import site

from rekall import plugin
from rekall.plugins import core

try:
    from rekall import ipython_support
except ImportError:
    ipython_support = None


class Notebook(plugin.Command):
    """Launch the IPython notebook."""

    __name = "notebook"

    @classmethod
    def is_active(cls, session):
        """Only active when the IPython notebook is actually installed."""
        try:
            import IPython.html.notebookapp  # pylint: disable=unused-variable

            return bool(ipython_support)
        except ImportError:
            return False


    def render(self, renderer):
        renderer.format("Starting IPython notebook.")
        renderer.format("Press Ctrl-c to return to the interactive shell.")
        ipython_support.NotebookSupport(self.session)


class Rekall(plugin.Command):
    """Starts a new rekall analysis session."""

    __name = "rekal"

    interactive = True

    @classmethod
    def args(cls, parser):
        super(Rekall, cls).args(parser)

        parser.add_argument("--filename",
                            help="The name of the image file to analyze.")

        parser.add_argument("--profile", default=None,
                            help="The name of the profile to load.")

        parser.add_argument("--verbose", default=False, action="store_true",
                            help="If set, enabled verbose mode.")

        parser.add_argument("--pager", default=None,
                            help="The name of a program to page output "
                            "(e.g. notepad or less).")

    def __init__(self, filename=None, profile=None, verbose=False,
                 pager=None, **kwargs):
        super(Rekall, self).__init__(**kwargs)

        self.filename = filename
        self.profile = profile
        self.verbose = verbose
        self.pager = pager

    def render(self, renderer):
        renderer.format("Initializing Rekall session.\n")

        with self.session.state as state:
            state.logging = "DEBUG" if self.verbose else "WARN"
            state.pager = self.pager
            state.filename = self.filename

            # Clear the profile from the session.
            self.session.profile = None
            state.profile = self.profile

        renderer.format("Done!\n")

# This sets python's built in help command so we can use the help command in the
# shell.

# pylint: disable=protected-access

class RekallHelper(site._Helper):
    """A More useful default help function."""
    HELP_MESSAGE = """Welocome to Rekall Memory Forensics.

To get started:

- Initialize the Rekall session using the rekall plugin. e.g.:

Win7SP1x64:pmem 13:36:23> rekall filename=r"\\\\.\\pmem", profile="Win7SP1x64", pager="notepad"

- Select a plugin to run by tying it in. e.g.:

Win7SP1x64:pmem 13:39:26> plugins.pslist

- You can complete any command by tapping Tab twice. Useful completions include:
  - File names on disk.
  - Plugin names.
  - Plugin parameters.

- Adding a ? after any plugin will print help about this plugin.

- You can get help on any module or object by typing:

help object

Some interesting topics to get you started, explaining some rekall specific
concepts:

help addrspace - The address space.
help obj       - The rekall objects.
help profile   - What are Profiles?
"""

    def __call__(self, item=None, **kwargs):
        if item is None:
            print self.HELP_MESSAGE
        else:
            print core.Info(item=item)

site._Helper = RekallHelper
