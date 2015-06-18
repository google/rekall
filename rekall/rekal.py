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

import logging
import pdb
import sys


from rekall import args
from rekall import config
from rekall import session

# Import and register the core plugins
from rekall import plugins  # pylint: disable=unused-import

from rekall.ui import text


config.DeclareOption(
    "-r", "--run", default=None,
    help="Run this script before dropping into the interactive shell.")


def main(argv=None):
    # New user interactive session (with extra bells and whistles).
    user_session = session.InteractiveSession()
    user_session.session_list.append(user_session)
    text_renderer = text.TextRenderer(session=user_session)

    with text_renderer.start():
        plugin_cls, flags = args.parse_args(argv=argv,
                                            user_session=user_session)

        # Determine if an external script needs to be run first.
        if getattr(flags, "run", None):
            # Export the session object to the external script.
            user_session.locals["session"] = user_session
            exec open(flags.run) in user_session.locals

    try:
        # Run the plugin with plugin specific args.
        user_session.RunPlugin(plugin_cls, **config.RemoveGlobalOptions(flags))
    except Exception as e:
        logging.fatal("%s. Try --debug for more information." % e)
        if getattr(flags, "debug", None):
            pdb.post_mortem(sys.exc_info()[2])
        raise
    finally:
        user_session.Flush()


if __name__ == '__main__':
    main()
