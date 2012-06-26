#!/usr/bin/python

# Volatility
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

"""Support ipython 12."""
from IPython.frontend.terminal.embed import InteractiveShellEmbed
from IPython.config.loader import Config
from IPython.core.completer import IPCompleter

banner = "Welcome to the volatility interactive shell! \nTo get help, type 'vhelp()'"


class VolCompleter(IPCompleter):

    def _default_arguments(self, obj):
        """Allow the object to return default args."""
        try:
            return obj._default_arguments()
        except AttributeError:
            return super(VolCompleter, self)._default_arguments(obj)


def Shell(user_session):
    # This should bring back the old autocall behaviour. e.g.:
    # In [1]: vol plugins.pslist
    cfg = Config()
    cfg.InteractiveShellEmbed.autocall = 2

    shell = InteractiveShellEmbed(config=cfg, user_ns=user_session._locals,
                                  banner2=banner)

    def _default_arguments(obj):
        """Allow the object to return default args."""
        try:
            return obj._default_arguments()
        except AttributeError:
            # Call the old implementation.
            return shell.Completer._default_arguments()

    shell.Completer._default_arguments = _default_arguments

    shell(local_ns=user_session._locals)

    return True
