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

import json
import logging
import os
import pdb
import sys
import time
import traceback

from rekall import addrspace
from rekall import config
from rekall import constants
from rekall import entity
from rekall import io_manager
from rekall import kb
from rekall import obj
from rekall import plugin
from rekall import registry
from rekall import utils

from rekall.ui import renderer
from rekall.ui import json_renderer


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

config.DeclareOption(
    "--output", default=None,
    help="If specified we write output to this file.")


class PluginContainer(object):
    """A container for plugins."""

    def __init__(self, session):
        self.session = session

    def __getattr__(self, attr):
        """Resolve plugin dynamically.

        Plugins may not be active depending on the current configuration.
        """
        # Try to see if the requested plugin is active right now.
        metadata = self.session.plugin_db.GetActivePlugin(attr)
        if metadata == None:
            return metadata

        return obj.Curry(metadata.plugin_cls, session=self.session)

    def __dir__(self):
        """Enumerate all active plugins in the current configuration."""
        return [
            cls.name for cls in plugin.Command.GetActiveClasses(self.session)
            if cls.name]


class Cache(utils.AttributeDict):
    def Get(self, item, default=None):
        if default is None:
            default = obj.NoneObject("%s not found in cache.", item)

        return super(Cache, self).Get(item) or default

    def __getattr__(self, attr):
        # Do not allow private attributes to be set.
        if attr.startswith("_"):
            raise AttributeError(attr)

        res = self.get(attr)
        if res is None:
            return obj.NoneObject("%s not set in cache", attr)

        return res

    def __str__(self):
        result = []
        for k, v in self.iteritems():
            if isinstance(v, obj.BaseObject):
                v = repr(v)

            value = "\n  ".join(str(v).splitlines())
            if len(value) > 1000:
                value = "%s ..." % value[:1000]

            result.append("  %s = %s" % (k, value))

        return "{\n" + "\n".join(sorted(result)) + "\n}"


class Configuration(Cache):
    # The session which owns this configuration object.
    session = None

    # This holds a write lock on the configuration object.
    _lock = False
    _pending_hooks = None

    _loaded_filename = None

    def __init__(self, session=None, **kwargs):
        super(Configuration, self).__init__(**kwargs)
        self.session = session
        self.update(**kwargs)
        self._pending_hooks = []

        # Can not update the configuration object any more.
        self._lock = 1


    def __repr__(self):
        return "<Configuration Object>"

    def _set_filename(self):
        """Callback for when a filename is set in the session.

        When the user changes the filename parameter we must reboot the session:

        - Reset the cache.
        - Update the filename
        - Reload the profile and possibly autodetect it.
        """
        filename = self.get('filename')
        if self.get('filename') != self._loaded_filename:
            self._loaded_filename = filename
            self['base_filename'] = os.path.basename(filename)

            if self.session:
                self.session.Reset()

    def _set_profile_path(self):
        # Flush the profile cache if we change the profile path.
        self['profile_path'] = self.profile_path
        self.session.profile_cache = {}
        self.session.UpdateFromConfigObject()

    def _set_profile(self):
        profile = self.Get("profile")
        if isinstance(profile, basestring):
            loaded_profile = self.session.LoadProfile(profile)
            if loaded_profile:
                with self:
                    self.Set("profile_obj", loaded_profile)

            else:
                raise RuntimeError(loaded_profile.reason)

        # The profile has changed - update the active plugin list.
        self.session.UpdateRunners()

    def _set_logging(self):
        level = self.logging
        if isinstance(level, basestring):
            level = getattr(logging, level.upper(), logging.INFO)

        if level == None:
            return

        logging.info("Logging level set to %s", level)
        logging.getLogger().setLevel(int(level))

    def Set(self, attr, value):
        if self._lock > 0:
            raise ValueError(
                "Can only update configuration using the context manager.")

        hook = getattr(self, "_set_%s" % attr, None)
        if hook:
            self._pending_hooks.append(hook)

        super(Configuration, self).Set(attr, value)

    def __enter__(self):
        # Allow us to update the context manager.
        self._pending_hooks = []
        self._lock -= 1

        return self

    def __exit__(self, exc_type, exc_value, trace):
        self._lock += 1

        # Run all the hooks _after_ all the parameters have been set.
        if self._lock == 1:
            pending_hooks = list(reversed(self._pending_hooks))
            for hook in pending_hooks:
                hook()


class ProgressDispatcher(object):
    """An object to manage progress calls.

    Since Rekall must be usable as a library it can not block for too
    long. Rekall makes continuous reports of its progress to the
    ProgressDispatcher, which then further dispatches them to other
    callbacks. This allows users of the Rekall library to be aware of how
    analysis is progressing. (e.g. to report it in a GUI).

    """

    def __init__(self):
        self.heap = []
        self.callbacks = {}

    def Register(self, key, callback):
        self.callbacks[key] = callback

    def UnRegister(self, key):
        self.callbacks.pop(key, 0)

    def Broadcast(self, message, *args, **kwargs):
        for handler in self.callbacks.values():
            handler(message, *args, **kwargs)


class Session(object):
    """Base session.

    This session contains the bare minimum to use rekall.
    """

    __metaclass__ = registry.MetaclassRegistry

    # The currently active address resolver.
    _address_resolver = None

    def __init__(self, **kwargs):
        self._parameter_hooks = {}

        # Store user configurable attributes here. These will be read/written to
        # the configuration file.
        kwargs.setdefault("cache", Cache())
        self.state = Configuration(self, **kwargs)

        self.progress = ProgressDispatcher()
        self.profile = obj.NoneObject("Set this to a valid profile "
                                      "(e.g. type profiles. and tab).")

        # Cache the profiles we get from LoadProfile() below.
        # TODO: This should probably be also done on disk somewhere to avoid
        # having to hit the profile repository all the time.
        self.profile_cache = {}

        entity.EntityManager.initialize()
        self.entities = entity.EntityManager(session=self)

        # A container for active plugins. This is done so that the interactive
        # console can see which plugins are active by simply command completing
        # on this object.
        self.plugins = PluginContainer(self)

        # This is a copy of the plugin metadata database.
        self.plugin_db = plugin.PluginMetadataDatabase(self)

        # The inventories is a local cache of all profiles available from all
        # repositories.
        self.inventories = {}
        with self:
            self.UpdateFromConfigObject()

        self._configuration_parameters = [x[2] for x in config.OPTIONS]

        # When the session switches process context we store various things in
        # this cache, so we can restore the context quickly. The cache is
        # indexed by the current process_context which can be found from
        # session.GetParameter("process_context").
        self.context_cache = {}

    def __enter__(self):
        # Allow us to update the context manager.
        self.state.__enter__()
        return self

    def __exit__(self, exc_type, exc_value, trace):
        self.state.__exit__(exc_type, exc_value, trace)

    def Reset(self):
        self.context_cache = {}
        self.profile_cache = {}
        self.physical_address_space = None
        self.kernel_address_space = None
        self.state.cache.clear()

    def UpdateFromConfigObject(self):
        """This method is called whenever the config object was updated.

        We are expected to re-check the config and re-initialize this session.
        """
        self.UpdateRunners()

        # Set the renderer.
        self.renderer = renderer.BaseRenderer.classes.get(
            self.GetParameter("renderer"), "TextRenderer")

    @property
    def address_resolver(self):
        """A convenience accessor for the address resolver implementation.

        Note that the correct address resolver implementation depends on the
        profile. For example, windows has its own address resolver, while Linux
        and OSX have a different one.
        """
        # Get the current process context.
        current_context = repr(self.GetParameter("process_context") or "Kernel")

        # Get the resolver from the cache.
        address_resolver = self.context_cache.get(current_context)
        if address_resolver == None:
            # Make a new address resolver.
            address_resolver = self.plugins.address_resolver()
            self.context_cache[current_context] = address_resolver

        return address_resolver

    def UpdateRunners(self):
        """Updates the plugins container with active plugins.

        Active plugins may change based on the profile/filename etc.
        """
        # Install parameter hooks.
        self._parameter_hooks = {}
        for cls in kb.ParameterHook.classes.values():
            if cls.is_active(self) and cls.name:
                self._parameter_hooks[cls.name] = cls(session=self)

        # Tell the entity manager to update the list of collectors.
        self.entities.update_collectors()

    def __getattr__(self, attr):
        """This will only get called if the attribute does not exist."""
        return obj.NoneObject("Attribute not set")

    def GetParameter(self, item, default=obj.NoneObject()):
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
        if result == None:
            # self.state.cache holds cached parameters. If the item is already
            # in the cache just return it, otherwise run the parameter hook.
            if item in self.state.cache:
                result = self.state.cache[item]
            else:
                result = self._RunParameterHook(item)

        if result == None:
            result = default

        return result

    def SetParameter(self, item, value):
        # Configuration parameters go in the state object, everything else goes
        # in the cache.
        if item in self._configuration_parameters:
            with self:
                self.state.Set(item, value)

        else:
            self.state.cache.Set(item, value)

    def _RunParameterHook(self, name):
        hook = self._parameter_hooks.get(name)
        if hook:
            result = hook.calculate()
            with self:
                self.SetParameter(name, result)

            return result

    def RunPlugin(self, plugin_obj, *pos_args, **kwargs):
        """Launch a plugin and its render() method automatically.

        We use the pager specified in session.GetParameter("pager").

        Args:
          plugin_obj: A string naming the plugin, or the plugin instance itself.
          *pos_args: Args passed to the plugin if it is not an instance.
          **kwargs: kwargs passed to the plugin if it is not an instance.
        """
        output = kwargs.pop("output", None)
        renderer = kwargs.pop("renderer", None)

        # Do we need to redirect output?
        if output is not None:
            with self:
                # Do not lose the global output redirection.
                old_output = self.GetParameter("output") or None
                self.SetParameter("output", output)
                try:
                    return self._RunPlugin(plugin_obj, renderer=renderer,
                                           *pos_args, **kwargs)
                finally:
                    self.SetParameter("output", old_output)

        else:
            return self._RunPlugin(plugin_obj, renderer=renderer,
                                   *pos_args, **kwargs)

    def _GetPluginObj(self, plugin_obj, *pos_args, **kwargs):
        if isinstance(plugin_obj, basestring):
            plugin_name = plugin_obj

        elif issubclass(plugin_obj, plugin.Command):
            plugin_name = plugin_obj.name
            plugin_cls = plugin_obj

        else:
            raise TypeError(
                "First parameter should be a plugin name or instance.")

        # When passed as a string this specifies a plugin name.
        if isinstance(plugin_obj, basestring):
            plugin_cls = getattr(self.plugins, plugin_obj, None)
            if plugin_cls is None:
                logging.error(
                    "Plugin %s is not active. Is it supported with "
                    "this profile?", plugin_name)
                return

        # Instantiate the plugin object.
        kwargs["session"] = self
        return plugin_cls(*pos_args, **kwargs)

    def _RunPlugin(self, plugin_obj, *pos_args, **kwargs):
        ui_renderer = kwargs.pop("renderer", None)
        if ui_renderer is None:
            ui_renderer = self.GetRenderer()

        # Start the renderer before instantiating the plugin to allow
        # rendering of reported progress in the constructor.
        try:
            plugin_obj = self._GetPluginObj(plugin_obj, *pos_args, **kwargs)
            with ui_renderer.start(plugin_name=plugin_obj.name, kwargs=kwargs):
                plugin_obj.render(ui_renderer)
                return plugin_obj

        except plugin.InvalidArgs as e:
            logging.error("Invalid Args: %s", e)

        except plugin.PluginError as e:
            ui_renderer.report_error(str(e))

        except KeyboardInterrupt:
            ui_renderer.report_error("Aborted")
            self.report_progress("Aborted!\r\n", force=True)

        except Exception, e:
            # Report the error to the renderer.
            ui_renderer.report_error(traceback.format_exc())

            # If anything goes wrong, we break into a debugger here.
            if self.GetParameter("debug"):
                pdb.post_mortem(sys.exc_info()[2])

            raise

        return plugin_obj

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

        # Only strip the extension if it is one of the recognized
        # extensions. Otherwise ignore it - this allows the profile name to have
        # . characters in it (e.g. Linux-3.1.13).
        canonical_name, extension = os.path.splitext(filename)
        if extension not in [".gz", ".json"]:
            canonical_name = filename

        try:
            if use_cache:
                cached_profile = self.profile_cache[canonical_name]
                if cached_profile:
                    return cached_profile

                else:
                    return obj.NoneObject(
                        "Unable to load profile %s from any repository." %
                        filename)

        except KeyError:
            pass

        # If the filename is a path we try to open it directly:
        if os.access(filename, os.R_OK):
            container = io_manager.Factory(os.path.dirname(filename))
            result = obj.Profile.LoadProfileFromData(
                container.GetData(os.path.basename(filename)),
                self, name=canonical_name)

        # Traverse the profile path until one works.
        else:
            result = None

            # The profile path is specified in search order.
            profile_path = self.state.Get("profile_path") or []

            # Add the last supported repository as the last fallback path.
            for path in profile_path:
                path = "%s/%s" % (path, constants.PROFILE_REPOSITORY_VERSION)

                # For now, print a warning when the user has an out of date
                # config file. TODO: Remove this in a future version.
                if "profiles.rekall.googlecode.com" in path:
                    logging.warn(
                        "Rekall profiles have moved to %s, but your .rekallrc "
                        "file still points to %s. You should update your "
                        "config file.",
                        constants.PROFILE_REPOSITORIES[0],
                        path)

                try:
                    manager = io_manager.Factory(path)
                    try:
                        # The inventory allows us to fail fetching the profile
                        # quickly - without making the round trip.
                        if path not in self.inventories:
                            # Fetch the profile inventory.
                            self.inventories[path] = manager.GetData(
                                "inventory")

                        inventory = self.inventories[path]["$INVENTORY"]
                        if (filename not in inventory and
                                filename + ".gz" not in inventory):
                            logging.debug(
                                "Skipped profile %s from %s (Not in inventory)",
                                filename, path)
                            continue

                    # No inventory in that repository - just try anyway.
                    except IOError:
                        pass

                    result = obj.Profile.LoadProfileFromData(
                        manager.GetData(filename), self,
                        name=canonical_name)
                    logging.info(
                        "Loaded profile %s from %s", filename, manager)

                    break

                except (IOError, KeyError) as e:
                    result = obj.NoneObject(e)
                    logging.debug("Could not find profile %s in %s: %s",
                                  filename, path, e)

                    continue

        # Cache it for later. Note that this also caches failures so we do not
        # retry again.
        self.profile_cache[canonical_name] = result
        if result == None:
            return obj.NoneObject(
                "Unable to load profile %s from any repository." % filename)

        return result

    def __unicode__(self):
        return u"Session"

    def report_progress(self, message=" %(spinner)s", *args, **kwargs):
        """Called by the library to report back on the progress."""
        self.progress.Broadcast(message, *args, **kwargs)

    def GetRenderer(self):
        """Get a renderer for this session.

        We instantiate the renderer specified in self.GetParameter("renderer").
        """
        ui_renderer = self.GetParameter("renderer", "text")
        if isinstance(ui_renderer, basestring):
            ui_renderer_cls = renderer.BaseRenderer.ImplementationByName(
                ui_renderer)
            ui_renderer = ui_renderer_cls(session=self)

        return ui_renderer

    @property
    def profile(self):
        res = self.state.Get("profile_obj")
        return res

    @profile.setter
    def profile(self, value):
        super(Configuration, self.state).Set("profile_obj", value)


class JsonSerializableSession(Session):
    """A session which can serialize its state into a Json file."""

    def SaveToFile(self, filename):
        with open(filename, "wb") as fd:
            logging.info("Saving session to %s", filename)
            json.dump(self.Serialize(), fd)

    def LoadFromFile(self, filename):
        try:
            lexicon, data = json.load(open(filename, "rb"))
            logging.info("Loaded session from %s", filename)

            self.Unserialize(lexicon, data)

        # decoding the session might fail un-expectantly - just discard the
        # session in that case.
        except Exception:
            # If anything goes wrong, we break into a debugger here.
            logging.error(traceback.format_exc())

            if self.GetParameter("debug"):
                pdb.post_mortem(sys.exc_info()[2])

    def Unserialize(self, lexicon, data):
        json_renderer_obj = json_renderer.JsonRenderer(session=self)
        decoder = json_renderer.JsonDecoder(self, json_renderer_obj)
        decoder.SetLexicon(lexicon)
        self.state = Configuration(**decoder.Decode(data))
        self.UpdateFromConfigObject()

    def Serialize(self):
        encoder = json_renderer.JsonEncoder(
            session=self, renderer="JsonRenderer")

        data = encoder.Encode(self.state)
        return encoder.GetLexicon(), data


class InteractiveSession(JsonSerializableSession):
    """The session allows for storing of arbitrary values and configuration.

    This session contains a lot of convenience features which are useful for
    interactive use.
    """

    def __init__(self, env=None, use_config_file=True, **kwargs):
        """Creates an interactive session.

        Args:
          env: If passed we use this dict as the local environment.

          use_config_file: If True we merge the system's config file into the
             session. This helps set the correct profile paths for example.

          kwargs: Arbitrary parameters to store in the session.

        Returns:
          an interactive session object.
        """
        self._locals = env or {}

        # These are the command plugins which we exported to the local
        # namespace.
        self._start_time = time.time()

        # These keep track of the last run plugin.
        self._last_plugin = None

        # Fill the session with helpful defaults.
        self.pager = obj.NoneObject("Set this to your favourite pager.")

        self.help_profile = None

        super(InteractiveSession, self).__init__()

        with self:
            if use_config_file:
                config.MergeConfigOptions(self.state)

            for k, v in kwargs.items():
                self.SetParameter(k, v)

            self.UpdateFromConfigObject()

    def PrepareLocalNamespace(self):
        session = self._locals['session'] = self
        # Prepopulate the namespace with our most important modules.
        self._locals['obj'] = obj
        self._locals['profile'] = self.profile
        self._locals['v'] = session.v

        # Some useful modules which should be available always.
        self._locals["sys"] = sys
        self._locals["os"] = os

        if not self.help_profile:
            self.help_profile = self.LoadProfile("help_doc")

        self._locals['plugins'] = PluginContainer(self)

        for cls in plugin.Command.GetActiveClasses(self):
            default_args, doc = "", ""
            if self.help_profile:
                default_args = self.help_profile.ParametersForPlugin(
                    cls.__name__)
                doc = self.help_profile.DocsForPlugin(cls.__name__)

            name = cls.name
            if name:
                # Create a runner for this plugin and set its documentation.
                runner = obj.Curry(
                    self.RunPlugin, name, default_arguments=default_args)

                runner.__doc__ = doc

                setattr(self._locals['plugins'], name, runner)
                self._locals[name] = runner

    def reset(self):
        """Reset the current session by making a new session."""
        self.PrepareLocalNamespace()

    def RunPlugin(self, *args, **kwargs):
        self.last = super(InteractiveSession, self).RunPlugin(*args, **kwargs)

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
""" % (time.ctime(self._start_time), self.state)
        return result

    def __dir__(self):
        items = self.__dict__.keys() + dir(self.__class__)

        return [x for x in items if not x.startswith("_")]

    def error(self, plugin_cls, e):
        """Swallow the error but report it."""
        logging.error("Failed running plugin %s: %s",
                      plugin_cls.name, e)
