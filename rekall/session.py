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
import sys
import time

from rekall import addrspace
from rekall import config
from rekall import io_manager
from rekall import plugin
from rekall import obj
from rekall import kb
from rekall import utils
from rekall.ui import renderer


# Top level args.
config.DeclareOption("-p", "--profile",
                     help="Name of the profile to load. This is the "
                     "filename of the profile found in the profiles "
                     "directory. Profiles are searched in the profile "
                     "path order.")

config.DeclareOption(
    "--profile_path", default=[], action="append",
    help="Path to search for profiles. This can take "
    "any form supported by the IO Manager (e.g. zip files, "
    "directories, URLs etc)")


config.DeclareOption("-f", "--filename",
                     help="The raw image to load.")

config.DeclareOption(
    "--buffer_size", default=20*1024*1024,
    action=config.IntParser,
    help="The maximum size of buffers we are allowed to read. "
    "This is used to control Rekall memory usage.")


class Container(object):
    """Just a container."""


class Cache(utils.AttributeDict):

    def _CheckCorrectType(self, value):
        """Ensure that the configuration remains json serializable."""
        if value is None:
            return True

        if isinstance(value, (int, long, basestring, float)):
            return True

        if isinstance(value, (list, tuple)):
            return all((self._CheckCorrectType(x) for x in value))

        if isinstance(value, dict):
            return (self._CheckCorrectType(value.keys()) and
                    self._CheckCorrectType(value.values()))

        return False

    def __str__(self):
        result = []
        for k, v in self.iteritems():
            if isinstance(v, obj.BaseObject):
                v = repr(v)

            value = "\n  ".join(str(v).splitlines())
            result.append("  %s = %s" % (k, value))

        return "{\n" + "\n".join(sorted(result)) + "\n}"

    def __repr__(self):
        return "<Configuration Object>"

    def _set_filename(self, filename):
        if filename:
            self['filename'] = filename
            self['base_filename'] = os.path.basename(filename)

            self.session.Reset()

    def _set_logging(self, value):
        level = value
        if isinstance(value, basestring):
            level = getattr(logging, value.upper(), logging.INFO)

        if level is None:
            return

        logging.info("Logging level set to %s", value)
        logging.getLogger().setLevel(int(level))

    def Set(self, attr, value):
        hook = getattr(self, "_set_%s" % attr, None)
        if hook:
            hook(value)

        else:
            if not self._CheckCorrectType(value):
                raise ValueError(
                    "Configuration parameters must be simple types, not %r." %
                    value)

            super(Cache, self).Set(attr, value)


class Configuration(Cache):
    # The session which owns this configuration object.
    session = None

    # This holds a write lock on the configuration object.
    _lock = False

    def __init__(self, session=None, **kwargs):
        super(Configuration, self).__init__(**kwargs)
        self.session = session
        self.update(**kwargs)

        # Can not update the configuration object any more.
        self._lock = True

    def Set(self, attr, value):
        if self._lock:
            raise ValueError(
                "Can only update configuration using the context manager.")

        super(Configuration, self).Set(attr, value)

    def __enter__(self):
        # Allow us to update the context manager.
        self._lock = False
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._lock = True
        if self.session:
            self.session.UpdateFromConfigObject()



class Session(object):
    """Base session.

    This session contains the bare minimum to use rekall.
    """
    def __init__(self, **kwargs):
        self._parameter_hooks = {}

        self.profile = obj.NoneObject("Set this to a valid profile "
                                      "(e.g. type profiles. and tab).")

        # Cache the profiles we get from LoadProfile() below.
        # TODO: This should probably be also done on disk somewhere to avoid
        # having to hit the profile repository all the time.
        self.profile_cache = {}

        # Store user configurable attributes here. These will be read/written to
        # the configuration file.
        self.state = Configuration(self, cache=Cache(), **kwargs)
        self.UpdateFromConfigObject()

    def Reset(self):
        self.physical_address_space = None
        self.kernel_address_space = None
        self.state.cache.clear()

    def UpdateFromConfigObject(self):
        """This method is called whenever the config object was updated.

        We are expected to re-check the config and re-initialize this session.
        """
        filename = self.state.filename
        if filename:
            # This may fire off the profile auto-detection code if a profile was
            # not provided by the user.
            profile_parameter = self.GetParameter("profile")
            if profile_parameter:
                self.profile = self.LoadProfile(profile_parameter)

        # Set the renderer.
        self.renderer = renderer.RendererBaseClass.classes.get(
            self.GetParameter("renderer"), "TextRenderer")

        # Make a new address resolver.
        self.address_resolver = kb.AddressResolver(self)

        self._update_runners()

    def _update_runners(self):
        self.plugins = Container()
        for cls in plugin.Command.GetActiveClasses(self):
            name = cls.name
            if name:
                setattr(self.plugins, name, obj.Curry(cls, session=self))

        # Install parameter hooks.
        self._parameter_hooks = {}
        for cls in kb.ParameterHook.classes.values():
            if cls.is_active(self) and cls.name:
                self._parameter_hooks[cls.name] = cls(session=self)

    def __getattr__(self, attr):
        """This will only get called if the attribute does not exist."""
        return None

    def GetParameter(self, item, default=None):
        """Retrieves a stored parameter.

        Parameters are managed by the Rekall session in two layers. The state
        containers contains those parameters which are deliberately set by the
        user.

        Some parameters are calculated by plugins and are used in order to speed
        up further calculations. These are cached in the state as well.

        It is important to never override a user selection by the cached
        results. Since the user must be allowed to override all parameters - for
        example through the GUI or the command line. Therefore when resolving a
        parameter, we first check in the state, and only if the parameter does
        not exist, we check the cache.
        """
        # The state holds user configuration from ~/.rekallrc.
        result = self.state.Get(item)
        if result is None:
            # self.state.cache holds cached parameters.
            result = self.state.cache.Get(item)
            if result is None:
                result = self._RunParameterHook(item)

        if result is None:
            result = default

        return result

    def SetParameter(self, item, value):
        if self.state.has_key(item):
            self.state[item] = value

        else:
            self.state.cache[item] = value

    def _RunParameterHook(self, name):
        hook = self._parameter_hooks.get(name)
        if hook:
            result = hook.calculate()
            if result is None:
                # Set a NoneObject here so that the hook does not get called
                # again - this effectively caches the failure of the hook in
                # returning anything useful. If you want to force the hook to
                # run again, actively store None for this parameters
                # (e.g. session.SetParameter("kdbg", None).
                result = obj.NoneObject(
                    "Parameter %s could not be calculated." % name)

            self.SetParameter(name, result)
            return result

    def error(self, _plugin_cls, e):
        """An error handler for plugin errors."""
        raise e

    def RunPlugin(self, plugin_cls, *pos_args, **kwargs):
        """Launch a plugin and its render() method automatically.

        We use the pager specified in session.GetParameter("pager").

        Args:
          plugin_cls: A string naming the plugin, or the plugin class itself.

          renderer: An optional renderer to use.

          debug: If set we break into the debugger if anything goes wrong.

          output: If set we open and write the output to this
            filename. Otherwise the output is redirected to stdout.
        """
        ui_renderer = kwargs.pop("renderer", None)
        fd = kwargs.pop("fd", None)
        debug = self.GetParameter("debug", False)
        pager = self.GetParameter("pager")

        # If the args came from the command line parse them now:
        flags = kwargs.get("flags")

        if isinstance(plugin_cls, basestring):
            plugin_name = plugin_cls
            plugin_cls = getattr(self.plugins, plugin_cls, None)
            if plugin_cls is None:
                logging.error("Plugin %s is not active. Is it supported with "
                              "this profile?", plugin_name)
                return

        if flags:
            from rekall import args

            kwargs = args.MockArgParser().build_args_dict(plugin_cls, flags)

        output = kwargs.pop("output", None)

        # Select the renderer from the session or from the kwargs.
        if not isinstance(ui_renderer, renderer.RendererBaseClass):
            ui_renderer_cls = self.renderer or renderer.TextRenderer

            if isinstance(ui_renderer_cls, basestring):
                ui_renderer_cls = renderer.TextRenderer.classes[ui_renderer_cls]

            # Allow the output to be written to file.
            if output is not None:
                fd = open(output, "w")
                pager = None

            # Allow per call overriding of the output file descriptor.
            paging_limit = self.GetParameter("paging_limit")
            if not pager:
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
            if (ui_renderer.isatty and pager and
                len(ui_renderer.data) >= self.state.paging_limit):
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

    def LoadProfile(self, filename, use_cache=True):
        """Try to load a profile directly from a filename.

        Args:
          filename: A string which will be used to get an io_manager
            container. If it contains a path sepearator we open the file
            directly, otherwise we search in the profile_path specification.

        Returns:
          a Profile() instance or a NoneObject()
        """
        if not filename:
            return

        if isinstance(filename, obj.Profile):
            return filename

        # We only want to deal with unix paths.
        filename = filename.replace("\\", "/")
        canonical_name = os.path.splitext(filename)[0]

        try:
            if use_cache:
                return self.profile_cache[canonical_name]
        except KeyError:
            pass

        # The filename is a path we try to open it directly:
        if filename.startswith("/") or filename.startswith("."):
            container = io_manager.Factory(os.path.dirname(filename))
            result = obj.Profile.LoadProfileFromData(
                container.GetData(os.path.basename(filename)),
                self, name=canonical_name)

        # Traverse the profile path until one works.
        else:
            result = None
            # The profile path is specified in search order.
            profile_path = self.state.Get("profile_path")

            # Make sure that we always fallback to the built in profiles last.
            if None not in profile_path:
                profile_path.append(None)

            for path in profile_path:
                try:
                    manager = io_manager.Factory(path)
                    result = obj.Profile.LoadProfileFromData(
                        manager.GetData(filename), self,
                        name=canonical_name)
                    logging.info("Loaded profile %s from %s",
                                 filename, manager)
                    break

                except (IOError, KeyError) as e:
                    result = obj.NoneObject(e)
                    logging.debug("Could not find profile %s in %s",
                                  filename, path)

                    continue

        if not result:
            raise ValueError("Unable to load profile %s from any repository." %
                             filename)

        # Cache it for later.
        self.profile_cache[canonical_name] = result

        return result

    def __unicode__(self):
        return u"Session"

    def report_progress(self, message=" %(spinner)s", *args, **kwargs):
        """Called by the library to report back on the progress."""
        if callable(self.progress):
            self.progress(message, *args, **kwargs)


class InteractiveSession(Session):
    """The session allows for storing of arbitrary values and configuration.

    This session contains a lot of convenience features which are useful for
    interactive use.
    """

    def __init__(self, env=None, **kwargs):
        self._locals = env or {}

        # These are the command plugins which we exported to the local
        # namespace.
        self._start_time = time.time()

        # These keep track of the last run plugin.
        self._last_plugin = None

        # Fill the session with helpful defaults.
        self.pager = obj.NoneObject("Set this to your favourite pager.")

        super(InteractiveSession, self).__init__(**kwargs)

    def _update_runners(self):
        super(InteractiveSession, self)._update_runners()

        self._locals['plugins'] = Container()
        for cls in plugin.Command.GetActiveClasses(self):
            name = cls.name
            if name:
                # Use the info class to build docstrings for all plugins.
                info_plugin = plugin.Command.classes['Info'](
                    cls, session=self)

                # Create a runner for this plugin and set its documentation.
                runner = obj.Curry(
                    self.RunPlugin, name, default_arguments=[
                        x for x, _ in info_plugin.get_default_args()])

                runner.__doc__ = utils.SmartUnicode(info_plugin)

                setattr(self._locals['plugins'], name, runner)
                self._locals[name] = runner

    def reset(self):
        """Reset the current session by making a new session."""
        self._prepare_local_namespace()

    def RunPlugin(self, *args, **kwargs):
        self.last = super(InteractiveSession, self).RunPlugin(*args, **kwargs)

    def _prepare_local_namespace(self):
        session = self._locals['session'] = self
        # Prepopulate the namespace with our most important modules.
        self._locals['addrspace'] = addrspace
        self._locals['obj'] = obj
        self._locals['profile'] = self.profile
        self._locals['v'] = session.v

        # Add all plugins to the local namespace and to their own container.
        self._update_runners()

        # Some useful modules which should be available always.
        self._locals["sys"] = sys
        self._locals["os"] = os

    def v(self):
        """Re-execute the previous command."""
        if self.last:
            self.RunPlugin(self.last)

    def lister(self, arg):
        for x in arg:
            self.printer(x)

    def __str__(self):
        result = """Rekall Memory Forensics session Started on %s.

Config:
%s
""" % (time.ctime(self.start_time), self.state)
        return result

    def __dir__(self):
        items = self.__dict__.keys() + dir(self.__class__)

        return [x for x in items if not x.startswith("_")]

    def error(self, plugin_cls, e):
        """Swallow the error but report it."""
        logging.error("Failed running plugin %s: %s",
                      plugin_cls.name, e)
