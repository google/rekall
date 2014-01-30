#!/usr/bin/python

# Rekall Memory Forensics
# Copyright 2013 Google Inc. All Rights Reserved.
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

"""Support IPython 1.0."""

# pylint: disable=protected-access

__author__ = "Michael Cohen <scudette@gmail.com>"

from rekall import config
from rekall import constants
from rekall import utils

try:
    from IPython.terminal import embed
except ImportError:
    try:
        from IPython.frontend.terminal import embed
    except ImportError:
        embed = None

from IPython.config.loader import Config


config.DeclareOption("--ipython_engine",
                     help="IPython engine, e.g. notebook.")


def RekallCompleter(self, text):
    command_parts = self.line_buffer.split(" ")
    command = command_parts[0]

    global_matches = set(self.global_matches(command))

    # Only complete if there is exactly one object which matches and a space was
    # typed after it. e.g.:
    # pslist <cursor>
    if (global_matches and len(global_matches) == 1 and
        len(command_parts) > 1):

        # Get the object and ask it about the list of default args.
        obj = self.namespace.get(global_matches.pop())
        try:
            matches = ["%s=" % x for x in obj.get_default_arguments()]
            return [x for x in matches if x.startswith(text)]
        except Exception:
            pass

    return []


def Shell(user_session):
    # This should bring back the old autocall behaviour. e.g.:
    # In [1]: pslist
    cfg = Config()
    cfg.InteractiveShellEmbed.autocall = 2

    cfg.PromptManager.in_template = (
        r'{color.LightCyan}'
        r'{session.state.base_filename}'
        r'{color.LightBlue}{color.Green} \T> ')

    cfg.PromptManager.in2_template = (
        r'{color.Green}|{color.LightGreen}\D{color.Green}> ')

    cfg.PromptManager.out_template = r'Out<\#> '
    cfg.InteractiveShell.separate_in = ''
    cfg.InteractiveShell.separate_out = ''
    cfg.InteractiveShell.separate_out2 = ''

    shell = embed.InteractiveShellEmbed(
        config=cfg, user_ns=user_session._locals)

    shell.Completer.merge_completions = False
    shell.banner = constants.BANNER
    shell.exit_msg = constants.GetQuote()
    shell.set_custom_completer(RekallCompleter, 0)

    # Do we need to pre-run something?
    if user_session.run is not None:
        execfile(user_session.run, user_session._locals)

    # Workaround for completer bug.
    import IPython.core.completerlib
    IPython.core.completerlib.get_ipython = lambda: shell

    shell(local_ns=user_session._locals)

    return True



def NotebookSupport(_):

    # The following only reveals hidden imports to pyinstaller.
    if False:
        import IPython.html.notebookapp
        import IPython.html.base.handlers
        import IPython.html.tree.handlers
        import IPython.html.auth.login
        import IPython.html.auth.logout
        import IPython.html.notebook.handlers
        import IPython.html.services.kernels.handlers
        import IPython.html.services.notebooks.handlers
        import IPython.html.services.clusters.handlers
        import IPython.kernel.ioloop
        import IPython.kernel.zmq.kernelapp

        import rekall.interactive

        import zmq.backend.cython
        import zmq.eventloop.ioloop

    argv = ["notebook", "-c",
            "from rekall import interactive; "
            "interactive.ImportEnvironment();", "--autocall", "2",
            "--notebook-dir",
            config.GetConfigFile().get("notebook_dir",
                                       config.GetHomeDir())
            ]

    import IPython

    IPython.start_ipython(argv=argv)
    return True
