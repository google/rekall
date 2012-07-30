#!/usr/bin/python

# Volatility
# Copyright (C) 2012 Michael Cohen <scudette@gmail.com>
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

import pdb
import logging
import sys


from volatility import args
from volatility import constants
from volatility import session

# Import and register the core plugins
from volatility import plugins


def IPython011Support(user_session):
    """Launch the ipython session for pre 0.12 versions.

    Returns:
      False if we failed to use IPython. True if the session was run and exited.
    """
    try:
        # Try to use the ipython shell
        from IPython import genutils
        from IPython import Shell

        # Fix a bug in IPython which prevents a custom __dir__ handler by
        # polluting it with additional crap.
        genutils.dir2 = dir

        shell = Shell.IPShellEmbed(argv=[], user_ns=user_session._locals,
                                   banner=constants.BANNER)

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

    # Try to enable tab completion
    try:
        import rlcompleter, readline #pylint: disable-msg=W0612
        readline.parse_and_bind("tab: complete")
    except ImportError:
        pass

    # Prepare the session for running within the native python interpreter.
    user_session._prepare_local_namespace()
    code.interact(banner=constants.BANNER, local=user_session._locals)

def UpdateSessionFromArgv(user_session, FLAGS):
    result = {}
    for k, v in FLAGS.__dict__.items():
        if v is not None:
            setattr(user_session, k.replace("-", "_"), v)
            result[k] = v

    return result

if __name__ == '__main__':
    FLAGS = args.parse_args()

    logging.basicConfig(level=logging.INFO)

    # New user interactive session (with extra bells and whistles).
    user_session = session.InteractiveSession()
    UpdateSessionFromArgv(user_session, FLAGS)

    if getattr(FLAGS, "module", None):
        UpdateSessionFromArgv(user_session, FLAGS)

        # Run the module
        try:
            user_session.vol(FLAGS.module, flags=FLAGS)
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
