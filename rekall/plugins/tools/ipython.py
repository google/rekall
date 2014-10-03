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
import os
import site

from rekall import constants
from rekall import plugin
from rekall import kb
from rekall.plugins import core
from rekall.ui import text as text_renderer

try:
    from rekall import ipython_support
except ImportError:
    ipython_support = None


def IPython012Support(user_session):
    """Launch the ipython session for post 0.12 versions.

    Returns:
      False if we failed to use IPython. True if the session was run and exited.
    """
    if ipython_support:
        # This must be run here because the IPython shell messes with our user
        # namespace above (by adding its own help function).
        user_session.PrepareLocalNamespace()

        return ipython_support.Shell(user_session)


def NativePythonSupport(user_session):
    """Launch the rekall session using the native python interpreter.

    Returns:
      False if we failed to use IPython. True if the session was run and exited.
    """
    # If the ipython shell is not available, we can use the native python shell.
    import code

    # Try to enable tab completion
    try:
        import rlcompleter, readline  # pylint: disable=W0612
        readline.parse_and_bind("tab: complete")
    except ImportError:
        pass

    # Prepare the session for running within the native python interpreter.
    user_session.PrepareLocalNamespace()
    code.interact(banner=constants.BANNER, local=user_session._locals)  # pylint: disable=protected-access


class Rekall(plugin.Command):
    """Starts or modifies a new rekall analysis session.

    This plugin is probably only useful within the interactive shell. It
    modifies the current state of the session. (The state can be viewed by
    printing the session parameter.

    Any session parameters can be set here. For example:

    rekal nocolors=True, paging_limit=10, pager="less"

    """
    __name = "rekal"

    interactive = True

    @classmethod
    def args(cls, parser):
        super(Rekall, cls).args(parser)

        parser.add_argument("--filename",
                            help="The name of the image file to analyze.")

        parser.add_argument("--profile", default=None,
                            help="The name of the profile to load.")

        parser.add_argument("--pager", default=None,
                            help="The name of a program to page output "
                            "(e.g. notepad or less).")

    def __init__(self, session=None, **kwargs):
        super(Rekall, self).__init__(session=session)
        self.kwargs = kwargs

    def render(self, renderer):
        renderer.format("Initializing Rekall session.\n")
        with self.session as s:
            for k, v in self.kwargs.items():
                s.SetParameter(k, v)

            s.UpdateFromConfigObject()


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


class PagingLimitHook(kb.ParameterHook):
    """If no paging_limit specified, calculate it from cursors."""
    name = "paging_limit"

    def calculate(self):
        if text_renderer.curses:
            return text_renderer.curses.tigetnum("lines")

        return int(os.environ.get("ROWS", 50))


class InteractiveShell(plugin.PhysicalASMixin, plugin.Command):
    """An interactive shell for Rekall."""

    name = "shell"

    PHYSICAL_AS_REQUIRED = False

    def render(self, renderer):
        self.session.mode = "Interactive"

        # Try to launch the session using ipython or bare python.
        if not IPython012Support(self.session):
            NativePythonSupport(self.session)

