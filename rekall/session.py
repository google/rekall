# Rekall Memory Forensics
# Copyright (C) 2012 Michael Cohen
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

"""This module implements the rekall session.

The session stores information about the a specific user interactive
session. Sessions can be saved and loaded between runs and provide a convenient
way for people to save their own results.
"""

__author__ = "Michael Cohen <scudette@gmail.com>"

import inspect
import logging
import pdb
import os
import subprocess
import sys
import textwrap
import time

from rekall import addrspace
# Include the built in profiles as a last fallback.
from rekall import builtin_profiles
from rekall import io_manager
from rekall import plugin
from rekall import obj
from rekall import registry
from rekall import utils
from rekall.ui import renderer



class Container(object):
    """Just a container."""


class Session(object):
    """Base session.

    This session contains the bare minimum to use rekall.
    """
    def __init__(self, **kwargs):
        self.profile = obj.NoneObject("Set this to a valid profile (e.g. type profiles. and tab).")

        # This means to use the built in profiles first.
        self.profile_path = [None]
        self.filename = obj.NoneObject("Set this to the image filename.")
        self.basename = obj.NoneObject("Unset")

        # The default renderer.
        self.renderer = "TextRenderer"
        self.paging_limit = None

        # Merge in defaults.
        self.UpdateFromArgs(kwargs)

    def UpdateFromArgs(self, args):
        """Update the session from a dict.

        If hooks are defines on some attributes which in turn access other
        attributes, it is difficult to enforce a proper dependency ordering. To
        avoid this issue we first set all the attributes on the session as they
        are, and then we run the hooks in arbitrary order. Those hooks which
        attempt to retrieve other session attributes will then be able to get it
        from the previosly set attributes.


        Args:
          args: A dict with keys - attributes to set, and values the attribute
             value.
        """
        hooks = []
        for attr, value in args.items():
            object.__setattr__(self, attr, value)

            hook = getattr(self, "_set_%s" % attr, None)
            if hook:
                hooks.append((hook, value))

        for hook, value in hooks:
            hook(value)

    def _update_runners(self):
        plugins = Container()
        object.__setattr__(self, "plugins", plugins)
        for cls in plugin.Command.GetActiveClasses(self):
            name = cls.name
            if name:
                # Create a runner for this plugin and set its documentation.
                setattr(plugins, name, obj.Curry(cls, session=self))

    def __setattr__(self, attr, value):
        """Allow the user to set configuration information directly."""
        # Allow for hooks to override special options.
        hook = getattr(self, "_set_%s" % attr, None)
        if hook:
            hook(value)
        else:
            object.__setattr__(self, attr, value)

            # This may affect which plugins are available for the user.
            self._update_runners()

    def __getattr__(self, attr):
        """This will only get called if the attribute does not exist."""
        return None
        return obj.NoneObject("Session has not attribute %s" % attr)

    def error(self, plugin_cls, e):
        """An error handler for plugin errors."""
        raise e

    def vol(self, plugin_cls, *pos_args, **kwargs):
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
        flags = kwargs.get("flags")

        if isinstance(plugin_cls, basestring):
            plugin_name = plugin_cls
            plugin_cls = getattr(self.plugins, plugin_cls, None)
            if plugin_cls is None:
                logging.error("Plugin %s is not active. Is it supported with "
                              "this profile?", plugin_name)
                return

        # If the args came from the command line parse them now:
        if flags:
            from rekall import args

            kwargs = args.MockArgParser().build_args_dict(plugin_cls, flags)

        # Select the renderer from the session or from the kwargs.
        if not isinstance(ui_renderer, renderer.RendererBaseClass):
            ui_renderer_cls = renderer.RendererBaseClass.classes.get(
                ui_renderer or self.renderer)

            if not ui_renderer_cls:
                logging.error("Unable to find a renderer %s. Using TextRenderer.",
                              ui_renderer or self.renderer)
                ui_renderer_cls = renderer.TextRenderer

            # Allow the output to be written to file.
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
            paging_limit = self.paging_limit
            if not self.pager:
                paging_limit = None

            ui_renderer = ui_renderer_cls(session=self, fd=fd,
                                          paging_limit=paging_limit)

        try:
            kwargs['session'] = self

            ui_renderer.start()

            # If we were passed an instance we do not instantiate it.
            if inspect.isclass(plugin_cls) or isinstance(plugin_cls, obj.Curry):
                result = plugin_cls(*pos_args, **kwargs)
            else:
                result = plugin_cls

            ui_renderer.start(plugin_name=result.name, kwargs=kwargs)

            try:
                result.render(ui_renderer)
            finally:
                ui_renderer.end()

            # If there was too much data and a pager is specified, simply pass
            # the data to the pager:
            if self.pager and len(ui_renderer.data) >= self.paging_limit:
                pager = renderer.Pager(self)
                for data in ui_renderer.data:
                    pager.write(data)

                # Now wait for the user to exit the pager.
                pager.flush()

            return result

        except plugin.InvalidArgs, e:
            logging.error("Invalid Args (Try info plugins.%s): %s",
                          plugin_cls.name, e)

        except plugin.Error, e:
            self.error(plugin_cls, e)

        except KeyboardInterrupt:
            if self.debug:
                pdb.post_mortem()

            self.report_progress("Aborted!\r\n", force=True)

        except Exception, e:
            logging.error("Error: %s", e)
            # If anything goes wrong, we break into a debugger here.
            if debug:
                pdb.post_mortem()
            else:
                raise

    def LoadProfile(self, filename):
        """Try to load a profile directly from a filename.

        Args:
          filename: A string which will be used to get an io_manager
            container. If it contains a path sepearator we open the file
            directly, otherwise we search in the profile_path specification.

        Returns:
          a Profile() instance or a NoneObject()
        """
        # We only want to deal with unix paths.
        filename = filename.replace("\\", "/")
        canonical_name = os.path.splitext(os.path.basename(filename))[0]

        # The filename is a path we try to open it directly:
        if "/" in filename:
            return obj.Profile.LoadProfileFromContainer(
                io_manager.Factory(filename), self, name=canonical_name)

        # Traverse the profile path until one works.
        result = None
        for path in reversed(self.profile_path):
            manager = io_manager.Factory(path)
            try:
                result = obj.Profile.LoadProfileFromContainer(
                    manager.OpenSubContainer(filename), self,
                    name=canonical_name)
                logging.info("Loaded profile %s from %s",
                             filename, manager)
                return result
            except (IOError, KeyError) as e:
                result = obj.NoneObject(e)
                logging.debug("Could not find profile %s in %s",
                              filename, manager)

        return result

    def _set_profile(self, profile):
        """A Hook for setting profiles."""
        # Profile is a string - we try to make a profile object.
        if isinstance(profile, basestring):
            profile = self.LoadProfile(profile)

        if profile != None and not isinstance(profile, obj.Profile):
            raise RuntimeError("A profile must be a string.")

        self.__dict__['profile'] = profile
        self._update_runners()

    def _set_filename(self, filename):
        if filename:
            self.__dict__['filename'] = filename
            self.__dict__['base_filename'] = os.path.basename(filename)

    def __unicode__(self):
        return u"Session"

    def report_progress(self, message="", *args, **kwargs):
        """Called by the library to report back on the progress."""
        if callable(self.progress):
            self.progress(message, *args, **kwargs)


class InteractiveSession(Session):
    """The session allows for storing of arbitrary values and configuration.

    This session contains a lot of convenience features which are useful for
    interactive use.
    """

    # This is used for setattr in __init__.
    _ready = False

    def __init__(self, env=None, **kwargs):
        self._locals = env or {}

        # These are the command plugins which we exported to the local
        # namespace.
        self._start_time = time.time()

        # These keep track of the last run plugin.
        self._last_plugin = None

        # Fill the session with helpful defaults.
        self.__dict__['logging'] = self.logging or "INFO"
        self.pager = obj.NoneObject("Set this to your favourite pager.")
        self.overwrite = False

        super(InteractiveSession, self).__init__(**kwargs)
        self.paging_limit = 50

        self._ready = True

    def _update_runners(self):
        plugins = Container()
        self._locals['plugins'] = Container()

        object.__setattr__(self, "plugins", plugins)
        for cls in plugin.Command.GetActiveClasses(self):
            name = cls.name
            if name:
                setattr(plugins, name, obj.Curry(cls, session=self))

                # Create a runner for this plugin and set its documentation.
                runner = obj.Curry(self.vol, name)

                # Use the info class to build docstrings for all plugins.
                info_plugin = plugin.Command.classes['Info'](cls)
                runner.__doc__ = utils.SmartUnicode(info_plugin)
                runner._default_arguments = [
                    x for x,y in info_plugin.get_default_args()]

                setattr(self._locals['plugins'], name, runner)
                self._locals[name] = runner

    def reset(self):
        """Reset the current session by making a new session."""
        self._prepare_local_namespace()

    def vol(self, *args, **kwargs):
        self.last = super(InteractiveSession, self).vol(*args, **kwargs)

    def _prepare_local_namespace(self):
        session = self._locals['session'] = self
        # Prepopulate the namespace with our most important modules.
        self._locals['addrspace'] = addrspace
        self._locals['obj'] = obj
        self._locals['profile'] = self.profile

        # The handler for the vol command.
        self._locals['vhelp'] = session.vhelp
        self._locals['v'] = session.v

        # Add all plugins to the local namespace and to their own container.
        self._update_runners()

        # Some useful modules which should be available always.
        self._locals["sys"] = sys
        self._locals["os"] = os

    def v(self):
        """Re-execute the previous command."""
        if self.last:
            self.vol(self.last)

    def lister(self, arg):
        for x in arg:
            self.printer(x)

    def __str__(self):
        result = """Rekall Memory Forensics session Started on %s.

Config:
""" % (time.ctime(self.start_time))
        for name in dir(self):
            value = getattr(self, name)
            result += " %s:  %r\n" % (name, value)

        return result

    def __dir__(self):
        items = self.__dict__.keys() + dir(self.__class__)

        return [x for x in items if not x.startswith("_")]

    def _set_logging(self, value):
        if value is None: return

        level = value
        if isinstance(value, basestring):
            level = getattr(logging, value.upper(), logging.INFO)

        logging.info("Logging level set to %s", value)
        logging.getLogger().setLevel(int(level))

    def error(self, plugin_cls, e):
        """Swallow the error but report it."""
        logging.error("Failed running plugin %s: %s",
                      plugin_cls.name, e)

    def vhelp(self, item=None):
        """Prints some helpful information."""
        if item is None:
            print """Welocome to Rekall Memory Forensics.

You can get help on any module or object by typing:

vhelp object

Some interesting topics to get you started, explaining some rekall specific
concepts:

vhelp addrspace - The address space.
vhelp obj       - The rekall objects.
vhelp profile   - What are Profiles?
"""
