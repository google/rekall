#!/usr/bin/env python

# Rekall
# Copyright (C) 2012 Michael Cohen <scudette@gmail.com>
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

__author__ = "Michael Cohen <scudette@gmail.com>"

# pylint: disable=protected-access

import os
import pdb
import logging
import sys


from rekall import args
from rekall import config
from rekall import constants
from rekall import obj
from rekall import session

# Import and register the core plugins
from rekall import plugins  # pylint: disable=unused-import

try:
    from rekall import ipython_support
except ImportError:
    ipython_support = None


config.DeclareOption(
    "-r", "--run", default=None,
    help="Run this script before dropping into the interactive shell.")



def IPython012Support(user_session):
    """Launch the ipython session for post 0.12 versions.

    Returns:
      False if we failed to use IPython. True if the session was run and exited.
    """
    if ipython_support:
        # This must be run here because the IPython shell messes with our user
        # namespace above (by adding its own help function).
        user_session._prepare_local_namespace()

        return ipython_support.Shell(user_session)


def NotebookSupport(user_session):
    engine = user_session.ipython_engine
    if not engine:
        return False

    if engine == "notebook":
        argv = ["notebook", "-c",
                "from rekall import interactive; "
                "interactive.ImportEnvironment();", "--autocall", "2"]
        import IPython

        IPython.start_ipython(argv=argv)
        return True
    else:
        raise RuntimeError("Unknown ipython mode %s" % engine)


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
    user_session._prepare_local_namespace()
    code.interact(banner=constants.BANNER, local=user_session._locals)

def main(argv=None):
    # IPython notebook launches the IPython kernel by re-spawning the main
    # binary with its own command line args. This hack traps this and diverts
    # execution to IPython itself.
    if len(sys.argv) > 2 and sys.argv[1] == "-c":
        to_run = sys.argv[2]
        if ".kernelapp" in to_run:
            exec(to_run)
            return

    # New user interactive session (with extra bells and whistles).
    user_session = session.InteractiveSession()

    flags = args.parse_args(argv=argv, user_session=user_session)

    # Determine if an external script needs to be run first.
    if getattr(flags, "run", None):
        exec open(flags.run) in user_session._locals

    # Run a module and do not drop into the shell.
    if getattr(flags, "module", None):
        # Run the module
        try:
            # Explicitly disable our handling of the pager since we are not
            # running in interactive mode.
            user_session.RunPlugin(flags.module, flags=flags, pager=None)
        except Exception as e:
            if getattr(flags, "debug", None):
                pdb.post_mortem(sys.exc_info()[2])
            else:
                logging.error("%s. Try --debug for more information." % e)

        sys.exit()

    # Interactive session, turn off object access logging since in interactive
    # mode, the user may use arbitrary object members.
    os.environ.pop(obj.ProfileLog.ENVIRONMENT_VAR, None)

    user_session.mode = "Interactive"

    # Try to launch the session using something.
    if user_session.state.ipython_engine == "notebook":
        ipython_support.NotebookSupport(user_session)
    else:
        _ = (IPython012Support(user_session) or
             NativePythonSupport(user_session))

if __name__ == '__main__':
    main()
