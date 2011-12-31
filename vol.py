#!/usr/bin/python
#  -*- mode: python; -*-
#
# Volatility
# Copyright (C) 2007,2008 Volatile Systems
#
# Original Source:
# Volatools Basic
# Copyright (C) 2007 Komoku, Inc.
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

"""
@author:       AAron Walters
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com
@organization: Volatile Systems
"""

#pylint: disable-msg=C0111
import sys

if sys.version_info < (2, 6, 0):
    sys.stderr.write("Volatiltiy requires python version 2.6, please upgrade your python installation.")
    sys.exit(1)

try:
    import psyco #pylint: disable-msg=W0611,F0401
except ImportError:
    pass

if False:
    # Include a fake import for things like pyinstaller to hit
    # since this is a dependency of the malware plugins
    import yara

import textwrap
from volatility import commands
from volatility import registry
import volatility.conf as conf
config = conf.ConfFactory()

import volatility.obj as obj
import volatility.utils as utils
import volatility.constants as constants
import volatility.debug as debug


def list_profiles():
    if config.PROFILE is not None and config.PROFILE != "list":
        return ""

    result = "\n\tAvailable Profiles:\n\n"
    for profile_name, profile_cls in sorted(obj.Profile.classes.items()):
        helpline = profile_cls.__doc__

        ## Just put the title line (First non empty line) in this
        ## abbreviated display
        for line in helpline.splitlines():
            if line:
                helpline = line
                break

        result += "\t\t{0:15}\t{1}\n".format(profile_name, helpline)

    return result

def list_plugins():
    if config.PROFILE:
        try:
            result = "\n\tSupported Plugin Commands for profile %s:\n\n" % config.PROFILE
            for cmdname, command_cls in sorted(commands.command.GetActiveClasses(config)):
                helpline = command_cls.help() or ''
                ## Just put the title line (First non empty line) in this
                ## abbreviated display
                for line in helpline.splitlines():
                    if line:
                        helpline = line
                        break

                result += "\t\t{0:15}\t{1}\n".format(cmdname, helpline)
        except Exception:
            import pdb; pdb.post_mortem()

        return result

def command_help(command_cls):
    result = textwrap.dedent("""
    ---------------------------------
    Module {0}
    ---------------------------------\n""".format(command_cls.__name__))

    return result + command_cls.help() + "\n\n"

def main():
    # Get the version information on every output from the beginning
    # Exceptionally useful for debugging/telling people what's going on
    sys.stderr.write("Volatile Systems Volatility Framework {0}\n".format(constants.VERSION))

    # Setup the debugging format
    debug.setup()

    # Reset the logging level now we know whether debug is set or not
    debug.setup(config.DEBUG)

    registry.PluginImporter(config.PLUGINS)

    ## Parse all the options now
    config.parse_options(False)
    command_cls = None

    # These are the modules which are currently active.
    available_modules = dict(commands.command.GetActiveClasses(config))

    ## Try to find the first thing that looks like a module name
    for m in config.args:
        if m in available_modules:
            command_cls = available_modules[m]
            break

    if not command_cls:
        config.parse_options(True)
        debug.error("You must specify something to do (try -h)")

    # If we get here we have a valid command class. We instantiate it and have it
    # register its options.
    config.set_help_hook(obj.Curry(command_help, command_cls))

    command_cls.register_options(config)

    # Should we allow options to be registered in the constructor? If there are
    # then we can not test for any of them in the constructor (because they are
    # not parsed yet).
    command_obj = command_cls(config)

    # This is the final parsing - all options should be accounted for now.
    config.parse_options(final=True)

    try:
        command_obj.execute()
    except utils.VolatilityException, e:
        print e

if __name__ == "__main__":
    config.set_usage(usage = "Volatility - A memory forensics analysis platform.")
    config.add_help_hook(list_profiles)
    config.add_help_hook(list_plugins)

    try:
        main()
    except Exception, ex:
        if config.DEBUG:
            debug.post_mortem()
        else:
            raise
    except KeyboardInterrupt:
        print "Interrupted"
