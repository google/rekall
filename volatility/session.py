# Volatility
# Copyright (C) 2012 Michael Cohen
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

"""This module implements the volatility session.

The session stores information about the a specific user interactive
session. Sessions can be saved and loaded between runs and provide a convenient
way for people to save their own results.
"""

__author__ = "Michael Cohen <scudette@gmail.com>"
import logging
import sys
import time

from volatility import addrspace
from volatility import conf
from volatility import plugin
from volatility import obj


class PluginContainer(object):
    """A container for holding plugins."""

    def __init__(self, config):
        self.plugins = {}
        self.config = config

        # Now add the commands that are available based on self.config
        for command_cls in plugin.Command.GetActiveClasses(self.config):
            self.plugins[command_cls.name] = command_cls

    def __dir__(self):
        """Support ipython command expansion."""
        return self.plugins.keys()

    def __getattr__(self, attr):
        try:
            return self.plugins[attr]
        except KeyError:
            raise AttributeError(attr)


class Session(object):
    """The session allows for storing of arbitrary values and configuration."""

    # This is used for setattr in __init__.
    ready = False

    def __init__(self):
        # These are the command plugins which we exported to the local
        # namespace.
        self.start_time = time.time()

        # Our global config object.
        self.config = conf.ConfObject()
        self.prepare_local_namespace()
        self.fd = sys.stdout

        self.ready = True

    def prepare_local_namespace(self):
        self.plugins = PluginContainer(self.config)
        # These are the local variables and methods.
        self.locals = dict(session=self, plugins=self.plugins, hh=self.help)

        # Prepopulate the namespace with our most important modules.
        self.locals['addrspace'] = addrspace
        self.locals['obj'] = obj

        # The handler for the vol command.
        self.locals['vol'] = self.vol

    def vol(self, plugin_cls, **kwargs):
        """Launch a plugin and its render() method automatically.

        Args:
          plugin: A string naming the plugin, or the plugin class itself.
        """
        if isinstance(plugin_cls, basestring):
            plugin_cls = getattr(self.plugins, plugin_cls)

        try:
            result = plugin_cls(session=self, **kwargs)
            result.render(self.fd)
        
            return result
        except plugin.Error, e:
            logging.error("Failed running plugin %s: %s", plugin_cls.__name__, e)

    def __repr__(self):
        return str(self)

    def __str__(self):
        return """Volatility session Started on %s.

Config:
%s
""" % (time.ctime(self.start_time), self.config)

    def __setattr__(self, attr, value):
        """Allow the user to set configuration information directly."""
        if self.ready:
            # Allow for hooks to override special options.
            hook = getattr(self, "set_%s" % attr)
            if hook:
                hook(value)
            else:
                setattr(self.config, attr, value)

            # This may affect which plugins are available for the user.
            self.locals['plugins'] = PluginContainer(self.config)
        else:
            object.__setattr__(self, attr, value)

    def __getattr__(self, attr):
        return getattr(self.config, attr)

    def __dir__(self):
        return dir(self.config)

    def set_profile(self, name):
        """A Hook for setting profiles."""
        # First try to find this profile.
        try:
            profile = obj.Profile.classes[name]
        except KeyError:
            logging.error("Profile %s is not known." % name)
            logging.info("Known profiles are:")

            for name in obj.Profile.classes:
                logging.info("  %s" % name)

            return

        self.config.profile = profile()

    def help(self, item=None):
        """Prints some helpful information."""
        if item is None:
            print """Welocome to Volatility.

You can get help on any module or object by typing:

help object

Some interesting topics to get you started, explaining some volatility specific
concepts:

help addrspace - The address space.
help obj       - The volatility objects.
help profile   - What are Profiles?
"""
