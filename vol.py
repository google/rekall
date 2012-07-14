#!/usr/bin/python

# Volatility
# Copyright (C) 2008 Volatile Systems
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

__author__ = "Michael Cohen <scudette@gmail.com>"

import argparse
import pdb
import logging
import sys


from volatility import session

# Import and register the core plugins
from volatility import plugins

class IntParser(argparse.Action):
    """Class to parse ints either in hex or as ints."""
    def __call__(self, parser, namespace, values, option_string=None):
        try:
            if values.startswith("0x"):
                values = int(values, 16)
            else:
                values = int(values)
        except ValueError:
            raise argparse.ArgumentError(self, "Invalid integer value")

        setattr(namespace, self.dest, values)


parser =  argparse.ArgumentParser(description='The Volatility Memory Forensic Framework.',
                                  epilog='When no module is provided, '
                                  'drops into interactive mode')

parser.add_argument("module", nargs='?',
                    help="plugin module to run.")

parser.add_argument("-e", "--exec", default=None,
                    help="execute a python volatility script.")

# The following are added for backwards compatibility to the most common
# volatility command line options. This is not an exhaustive list (particularly
# since in Volatility 2.X further options can be added to each plugin).

parser.add_argument("-i", "--interactive", default=False, action="store_true",
                    help="For compatibility, if a plugin name is specified on the "
                    "command line, we exit immediately after running it. If this flag "
                    "is specified we drop into the interactive shell instead.")

parser.add_argument("-f", "--filename", default=None,
                    help="The raw image to load.")

parser.add_argument("-p", "--profile", default=None,
                    help="Name of the profile to load.")

parser.add_argument("--dtb", action=IntParser, help="DTB Address.")
parser.add_argument("--pid", help="A process PID.", action=IntParser)
parser.add_argument("--eprocess", help="An process kernel address.", action=IntParser)

parser.add_argument("--dump-dir", help="The directory to dump files to.")

parser.add_argument("--logging", default=None,
                    help="Logging level (lower is more verbose).")

parser.add_argument("--debug", default=None, action="store_true",
                    help="If set we break into the debugger on some conditions.")

parser.add_argument("--renderer", default="TextRenderer",
                    help="The renderer to use. e.g. (TextRenderer, JsonRenderer).")

parser.add_argument("-v", "--verbose", default=None, action="store_true",
                    help="Verbosity level for plugins.")


def IPython011Support(user_session):
    """Launch the ipython session for pre 0.12 versions.

    Returns:
      False if we failed to use IPython. True if the session was run and exited.
    """
    banner = "Welcome to the volatility interactive shell! \nTo get help, type 'vhelp()'"

    try:
        # Try to use the ipython shell
        from IPython import genutils
        from IPython import Shell

        # Fix a bug in IPython which prevents a custom __dir__ handler by
        # polluting it with additional crap.
        genutils.dir2 = dir

        shell = Shell.IPShellEmbed(argv=[], user_ns=user_session._locals, banner=banner)

        # This must be run here because the IPython shell messes with our user
        # namespace above (by adding its own help function).
        user_session._prepare_local_namespace()
        UpdateSessionFromArgv(user_session, FLAGS)

        shell(local_ns=user_session._locals)
        return True

    except ImportError:
        return False

def IPython012Support(user_session):
    """Launch the ipython session for post 0.12 versions.

    Returns:
      False if we failed to use IPython. True if the session was run and exited.
    """
    banner = "Welcome to volshell! \nTo get help, type 'help()'"

    try:
        from volatility import ipython_support

        # This must be run here because the IPython shell messes with our user
        # namespace above (by adding its own help function).
        user_session._prepare_local_namespace()
        UpdateSessionFromArgv(user_session._locals['session'], FLAGS)

        return ipython_support.Shell(user_session)
    except ImportError:
        return False


def NativePythonSupport(user_session):
    """Launch the volatility session using the native python interpreter.

    Returns:
      False if we failed to use IPython. True if the session was run and exited.
    """
    # If the ipython shell is not available, we can use the native python shell.
    import code, inspect

    banner = "Welcome to volshell! \nTo get help, type 'help()'"

    # Try to enable tab completion
    try:
        import rlcompleter, readline #pylint: disable-msg=W0612
        readline.parse_and_bind("tab: complete")
    except ImportError:
        pass

    # Prepare the session for running within the native python interpreter.
    user_session._prepare_local_namespace()
    code.interact(banner = banner, local = user_session._locals)

def UpdateSessionFromArgv(user_session, FLAGS):
    result = {}
    for k, v in FLAGS.__dict__.items():
        if v is not None:
            setattr(user_session, k.replace("-", "_"), v)
            result[k] = v

    return result

if __name__ == '__main__':
    FLAGS = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    # New user session.
    user_session = session.Session()
    UpdateSessionFromArgv(user_session, FLAGS)

    if FLAGS.module:
        UpdateSessionFromArgv(user_session, FLAGS)

        # Run the module
        try:
            user_session.vol(FLAGS.module)
        except Exception as e:
            if FLAGS.debug:
                pdb.post_mortem()
            else:
                logging.error("%s. Try --debug for more information." % e)

        if not FLAGS.interactive:
            sys.exit()

    # Try to launch the session using something.
    (IPython011Support(user_session) or
     IPython012Support(user_session) or
     NativePythonSupport(user_session))
