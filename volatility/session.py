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
import subprocess
import sys
import textwrap
import time

from volatility import addrspace
from volatility import plugin
from volatility import obj
from volatility import registry
from volatility import utils
from volatility.ui import renderer


class ProfileContainer(object):
    """A utility class for intantiating profiles."""

    def __init__(self, session=None):
        self.session = session

    def __dir__(self):
        """Show all available profiles."""
        return obj.Profile.classes.keys()

    def __getattr__(self, attr):
        if attr not in obj.Profile.classes:
            raise AttributeError("%s is not a valid profile" % attr)

        return attr


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


class Session(object):
    """The session allows for storing of arbitrary values and configuration."""

    # This is used for setattr in __init__.
    _ready = False

    def __init__(self, env=None, **kwargs):
        # These are the command plugins which we exported to the local
        # namespace.
        self._start_time = time.time()
        self._locals = env or {}

        # Fill the session with helpful defaults.
        self.__dict__['logging'] = self.logging or "INFO"
        self.pager = obj.NoneObject("Set this to your favourite pager.")
        self.profile = obj.NoneObject("Set this a valid profile (e.g. type profiles. and tab).")
        self.profile_file = obj.NoneObject("Some profiles accept a data file (e.g. Linux).")
        self.filename = obj.NoneObject("Set this to the image filename.")

        # The default renderer.
        self.renderer = "TextRenderer"
        self.overwrite = False

        self.plugins = PluginContainer(self)
        self._ready = True

        # Merge in defaults.
        for k, v in kwargs.items():
            setattr(self, k, v)

    def reset(self):
        """Reset the current session by making a new session."""
        self._prepare_local_namespace()

    def _prepare_local_namespace(self):
        session = self._locals['session'] = Session(self._locals)

        # Prepopulate the namespace with our most important modules.
        self._locals['addrspace'] = addrspace
        self._locals['obj'] = obj
        self._locals['plugins'] = session.plugins
        self._locals['profiles'] = ProfileContainer(self)

        # The handler for the vol command.
        self._locals['dump'] = session.dump
        self._locals['vol'] = session.vol
        self._locals['info'] = session.info
        self._locals['vhelp'] = session.vhelp
        self._locals['p'] = session.printer
        self._locals['l'] = session.lister
        self._locals['dis'] = obj.Curry(session.vol, "dis")

    def printer(self, string):
        print string

    def lister(self, arg):
        for x in arg:
            self.printer(x)

    def dump(self, target, offset=0, width=16, rows=10):
        # Its an object
        if isinstance(target, obj.BaseObject):
            data = target.obj_vm.zread(target.obj_offset, target.size())
            base = target.obj_offset
        # Its an address space
        elif isinstance(target, addrspace.BaseAddressSpace):
            data = target.zread(offset, width*rows)
            base = int(offset)
        # Its a string or something else:
        else:
            data = utils.SmartStr(target)
            base = 0

        utils.WriteHexdump(sys.stdout, data, width=width, base=base)

    def info(self, plugin_cls=None, fd=None):
        self.vol(self.plugins.info, item=plugin_cls, fd=fd)

    def vol(self, plugin_cls, *args, **kwargs):
        """Launch a plugin and its render() method automatically.

        We use the pager specified in session.pager.

        Args:
          plugin_cls: A string naming the plugin, or the plugin class itself.
          renderer: An optional renderer to use.
          debug: If set we break into the debugger if anything goes wrong.

          output: If set we open and write the output to this filename. If
            session.overwrite is set to True, we will overwrite this
            file. Otherwise the output is redirected to stdout.
        """
        ui_renderer = kwargs.pop("renderer", None)
        fd = kwargs.pop("fd", None)
        debug = kwargs.pop("debug", False)
        output = kwargs.pop("output", None)
        overwrite = kwargs.get("overwrite")

        if isinstance(plugin_cls, basestring):
            plugin_cls = getattr(self.plugins, plugin_cls)

        # Select the renderer from the session or from the kwargs.
        if not isinstance(ui_renderer, renderer.RendererBaseClass):
            try:
                ui_renderer_cls = renderer.RendererBaseClass.classes[
                    ui_renderer or self.renderer]
            except KeyError:
                logging.error("Unable to find a renderer %s. Using TextRenderer.",
                              ui_renderer or self.renderer)
                ui_renderer_cls = renderer.TextRenderer

            if output is not None:
                if os.access(output, os.F_OK) and not (
                    overwrite or self.overwrite):
                    logging.error(
                        "Output file '%s' exists but session.overwrite is "
                        "not set." % output)
                    return
                else:
                    fd = open(output, "w")

            # Allow per call overriding of the output file descriptor.
            ui_renderer = ui_renderer_cls(session=self, fd=fd)

        try:
            ui_renderer.start(plugin_name=plugin_cls.name, kwargs=kwargs)

            kwargs['session'] = self
            result = plugin_cls(*args, **kwargs)
            try:
                result.render(ui_renderer)
            except KeyboardInterrupt:
                self.report_progress("Aborted!\r\n", force=True)

            finally:
                ui_renderer.end()

            return result

        except plugin.InvalidArgs, e:
            logging.warning("Invalid Args (Try info plugins.%s): %s",
                            plugin_cls.name, e)

        except plugin.Error, e:
            logging.error("Failed running plugin %s: %s",
                          plugin_cls.name, e)

        except Exception, e:
            logging.error("Error: %s", e)
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
        if profile == None:
            self.__dict__['profile'] = profile
            return

        # Profile is a string - we try to make a profile object.
        if isinstance(profile, basestring):
            # First try to find this profile.
            try:
                profile = obj.Profile.classes[profile](session=self)
            except KeyError:
                logging.error("Profile %s is not known." % profile)
                logging.info("Known profiles are:")

                for profile in obj.Profile.classes:
                    logging.info("  %s" % profile)

                return

        if isinstance(profile, obj.Profile):
            self.__dict__['profile'] = profile
            self.plugins.reset()
        else:
            raise RuntimeError("A profile must be a string.")

    def _set_logging(self, value):
        if value is None: return

        level = value
        if isinstance(value, basestring):
            level = getattr(logging, value, logging.INFO)

        logging.log(level, "Logging level set to %s", value)
        logging.getLogger().setLevel(int(level))

    def report_progress(self, message="", force=False):
        """Called by the library to report back on the progress."""
        if callable(self.progress):
            self.progress(message, force=force)

    def vhelp(self, item=None):
        """Prints some helpful information."""
        if item is None:
            print """Welocome to Volatility.

You can get help on any module or object by typing:

vhelp object

Some interesting topics to get you started, explaining some volatility specific
concepts:

vhelp addrspace - The address space.
vhelp obj       - The volatility objects.
vhelp profile   - What are Profiles?
"""
