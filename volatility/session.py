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
import pdb
import os
import sys
import time

from volatility import addrspace
from volatility import plugin
from volatility import obj


class PluginContainer(object):
    """A container for holding plugins."""

    def __init__(self, session):
        self.plugins = {}
        self.session = session

        # Now add the commands that are available based on self.session
        for command_cls in plugin.Command.GetActiveClasses(self.session):
            if command_cls.name:
                self.plugins[command_cls.name] = command_cls

        logging.debug("Reloading active plugins %s", 
                      ["%s <- %s" % (x, y.__name__) for x,y in self.plugins.items()])

    def reset(self):
        self.__init__(self.session)

    def __dir__(self):
        """Support ipython command expansion."""
        return self.plugins.keys()

    def __getattr__(self, attr):
        try:
            return self.plugins[attr]
        except KeyError:
            raise AttributeError(attr)


class Pager(object):
    """A file like object which can be swapped with a pager."""
    # Default encoding is utf8
    encoding = "utf8"

    def __init__(self, session=None, default_fd=None):
        # Default fd if not pager can be found.
        self.default_fd = default_fd or sys.stdout
        self.make_pager(session)

        
    def make_pager(self, session):
        # More is the least common denominator of pagers :-(. Less is better,
        # but most is best!
        pager = session.pager or os.environ.get("PAGER")
        try:
            self.pager = os.popen(pager, 'w', 0)
        except Exception:
            self.pager = self.default_fd

        # Determine the output encoding
        try:
            encoding = self.pager.encoding
            if encoding: self.encoding = encoding
        except AttributeError:
            pass

    def write(self, data):
        # Encode the data according to the output encoding.
        data = data.encode(self.encoding)
        try:
            self.pager.write(data)
        except IOError:
            # In case the pipe closed we just write to stdout
            self.pager = sys.stdout
            self.pager.write(data)


class Session(object):
    """The session allows for storing of arbitrary values and configuration."""

    # This is used for setattr in __init__.
    _ready = False

    def __init__(self, env=None):
        # These are the command plugins which we exported to the local
        # namespace.
        self._start_time = time.time()
        self._locals = env or {}
        self.plugins = PluginContainer(self)
        self._ready = True

    def reset(self):
        """Reset the current session by making a new session."""
        self._prepare_local_namespace()

    def _prepare_local_namespace(self):
        session = self._locals['session'] = Session(self._locals)

        # Prepopulate the namespace with our most important modules.
        self._locals['addrspace'] = addrspace
        self._locals['obj'] = obj
        self._locals['plugins'] = session.plugins

        # The handler for the vol command.
        self._locals['vol'] = session.vol
        self._locals['info'] = session.info
        self._locals['help'] = session.help

    def info(self, plugin_cls=None, fd=None):
        self.vol(self.plugins.info, item=plugin_cls, fd=fd)

    def vol(self, plugin_cls=None, fd=None, debug=False, **kwargs):
        """Launch a plugin and its render() method automatically.

        Args:
          plugin: A string naming the plugin, or the plugin class itself.
          fd: A file descriptor to write the rendered result to. If not set we
            use the pager class.
          debug: If set we break into the debugger if anything goes wrong.
        """
        if isinstance(plugin_cls, basestring):
            plugin_cls = getattr(self.plugins, plugin_cls)

        try:
            # Wrap the file descriptor with a pager that takes care of encoding.
            fd = Pager(session=self, default_fd=fd)

            kwargs['session'] = self
            result = plugin_cls(**kwargs)
            result.render(fd)
            
            return result
        except plugin.Error, e:
            logging.error("Failed running plugin %s: %s", plugin_cls.__name__, e)
        except Exception:
            # If anything goes wrong, we break into a debugger here.
            if debug:
                pdb.post_mortem()
            else:
                raise

    def __str__(self):
        result = """Volatility session Started on %s.

Config:
""" % (time.ctime(self.start_time))
        for name in dir(self):
            value = getattr(self, name)
            result += " %s:  %r\n" % (name, value)

        return result

    def __setattr__(self, attr, value):
        """Allow the user to set configuration information directly."""
        # Allow for hooks to override special options.
        hook = getattr(self, "_set_%s" % attr, None)
        if hook:
            hook(value)
        else:
            object.__setattr__(self, attr, value)

        # This may affect which plugins are available for the user.
        if self.plugins:
            self.plugins.reset()

    def __getattr__(self, attr):
        """This will only get called if the attribute does not exist."""
        return None

    def __dir__(self):
        items = self.__dict__.keys() + dir(self.__class__)

        return [x for x in items if not x.startswith("_")]

    def _set_profile(self, profile):
        """A Hook for setting profiles."""
        # Profile is a string - we try to make a profile object.
        if isinstance(profile, basestring):
            # First try to find this profile.
            try:
                profile = obj.Profile.classes[profile]()
            except KeyError:
                logging.error("Profile %s is not known." % name)
                logging.info("Known profiles are:")
            
                for name in obj.Profile.classes:
                    logging.info("  %s" % name)

                return
        if isinstance(profile, obj.Profile):
            self.__dict__['profile'] = profile
            self.plugins.reset()
        else:
            raise RuntimeError("A profile must be a string.")

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
