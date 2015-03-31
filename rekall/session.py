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

from rekall import config
from rekall import io_manager
from rekall import kb
from rekall import obj
from rekall import plugin
from rekall import registry
from rekall import utils

from rekall.entities import manager as entity_manager
from rekall.ui import renderer
from rekall.ui import json_renderer


config.DeclareOption(
    "--repository_path", default=[], type="ArrayStringParser",
    help="Path to search for profiles. This can take "
    "any form supported by the IO Manager (e.g. zip files, "
    "directories, URLs etc)")

config.DeclareOption("-f", "--filename",
                     help="The raw image to load.")

config.DeclareOption(
    "--buffer_size", default=20*1024*1024,
    type="IntParser",
    help="The maximum size of buffers we are allowed to read. "
    "This is used to control Rekall memory usage.")

config.DeclareOption(
    "--output", default=None,
    help="If specified we write output to this file.")

config.DeclareOption(
    "--max_collector_cost", default=4, type="IntParser",
    help="If specified, collectors with higher cost will not be used.")


class PluginContainer(object):
    """A container for plugins.

    Dynamically figures out which plugins are active given the current session
    state (profile, image file etc).
    """

    def __init__(self, session):
        self.session = session
        self.plugin_db = plugin.PluginMetadataDatabase(session)

    def GetPluginClass(self, name):
        """Return the active plugin class that implements plugin name.

        Plugins may not be active depending on the current configuration.
        """
        # Try to see if the requested plugin is active right now.
        metadata = self.plugin_db.GetActivePlugin(name)
        if metadata == None:
            return metadata

        return metadata.plugin_cls

    def Metadata(self, name):
        return self.plugin_db.GetActivePlugin(name)

    def __getattr__(self, name):
        """Gets a wrapped active plugin class.

        A convenience function that returns a curry wrapping the plugin class
        with the session parameter so users do not need to explicitly pass the
        session.

        This makes it easy to use in the interactive console:

        pslist_plugin = plugins.pslist()
        """
        plugin_cls = self.GetPluginClass(name)
        if plugin_cls == None:
            return plugin_cls

        return obj.Curry(plugin_cls, session=self.session)

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
        """Print the contents somewhat concisely."""
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
    """The session's configuration is managed through this object.

    The session can be configured using the SetParameter() method. However,
    sometimes when a certain parameter is modified, some code needs to run in
    response. For example, if the filename is modified, the profile must be
    recalculated.

    It is not sufficient to attach setter methods to every such parameter
    though, because there is no guarantee which order these parameters are
    configured. For example, suppose we want to set both the filename and the
    profile:

    session.SetParameter("filename", filename)
    session.SetParameter("profile", "nt/...")

    Since the profile is explicitly set we should not guess it, but if a simple
    set hook is used, there is no way for the _set_filename() hook to determine
    that the profile is explicitly given. So what will happen now is that the
    filename will be changed, then a profile will be autodetected, then it will
    be immediately overwritten with the user set profile.

    To avoid this issue we use a context manager to essentially group
    SetParameter() calls into an indivisible unit. The hooks are all run _after_
    all the parameters are set:

    with session:
        session.SetParameter("filename", filename)
        session.SetParameter("profile", "nt/...")

    Now the _set_filename() hook can see that the profile is explicitly set so
    it should not be auto-detected.

    Upon entering the context manager, we create a new temporary place to store
    configuration parameters. Then, when exiting the context manager we ensure
    that those parameters with hooks are called. The hooks are passed the newly
    set parameters. Each hook returns the value that will actually be set in the
    session (so the hook may actually modify the value).
    """
    # The session which owns this configuration object.
    session = None

    # This holds a write lock on the configuration object.
    _lock = False
    _pending_parameters = None
    _pending_hooks = None

    _loaded_filename = None

    def __init__(self, session=None, **kwargs):
        super(Configuration, self).__init__(**kwargs)
        self.session = session

        # These will be processed on exit from the context manager.
        self._pending_parameters = {}
        self._pending_hooks = []

        # Can not update the configuration object any more.
        self._lock = 1

    def __repr__(self):
        return "<Configuration Object>"

    def _set_filename(self, filename, parameters):
        """Callback for when a filename is set in the session.

        When the user changes the filename parameter we must reboot the session:

        - Reset the cache.
        - Update the filename
        - Reload the profile and possibly autodetect it.
        """
        if filename:
            # This is used by the ipython prompt.
            self.Set('base_filename', os.path.basename(filename))

        # Reset any caches.
        if self.session:
            self.session.Reset()

        # If a profile is not configured at this time, we need to auto-detect
        # it.
        if 'profile' not in parameters:
            # Clear the existing profile and trigger profile autodetection.
            del self['profile']
            self['filename'] = filename

        return filename

    def _set_repository_path(self, profile_path, _):
        # Flush the profile cache if we change the profile path.
        self.session.profile_cache = {}

        return profile_path

    def _set_profile(self, profile, _):
        profile_obj = self.session.LoadProfile(profile)
        if profile_obj:
            self.cache.Set("profile_obj", profile_obj)

        return profile

    def _set_logging(self, level, _):
        if isinstance(level, basestring):
            level = getattr(logging, level.upper(), logging.INFO)

        if level == None:
            return

        logging.info("Logging level set to %s", level)
        logging.getLogger().setLevel(int(level))

    def _set_ept(self, ept, _):
        self.session.Reset()
        return ept

    def _set_session_name(self, name, _):
        self.session.session_name = name
        return name

    def _set_session_id(self, session_id, __):
        if self.Get("session_id") == None:
            return session_id

        # We are allowed to set a session id which is not already set.
        for session in self.session.session_list:
            if session_id == session.session_id:
                raise RuntimeError("Session_id clashes with existing session.")

        return session_id

    def Set(self, attr, value):
        hook = getattr(self, "_set_%s" % attr, None)
        if hook:
            # If there is a set hook we must use the context manager.
            if self._lock > 0:
                raise ValueError(
                    "Can only update attribute %s using the context manager." %
                    attr)

            if attr not in self._pending_hooks:
                self._pending_hooks.append(attr)

            self._pending_parameters[attr] = value
        else:
            super(Configuration, self).Set(attr, value)

    def __delitem__(self, item):
        try:
            super(Configuration, self).__delitem__(item)
        except KeyError:
            pass

    def __enter__(self):
        self._lock -= 1

        return self

    def __exit__(self, exc_type, exc_value, trace):
        self._lock += 1

        # Run all the hooks _after_ all the parameters have been set.
        if self._lock == 1:
            while self._pending_hooks:
                hooks = list(reversed(self._pending_hooks))
                self._pending_hooks = []

                # Allow the hooks to call Set() by temporarily entering the
                # context manager.
                with self:
                    # Hooks can call Set() which might add more hooks.
                    for attr in hooks:
                        hook = getattr(self, "_set_%s" % attr)
                        value = self._pending_parameters[attr]

                        res = hook(value, self._pending_parameters)
                        if res is None:
                            res = value

                        self._pending_parameters[attr] = res

            self.update(**self._pending_parameters)
            self._pending_parameters = {}


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
        self.progress = ProgressDispatcher()

        # Cache the profiles we get from LoadProfile() below.
        # TODO: This should probably be also done on disk somewhere to avoid
        # having to hit the profile repository all the time.
        self.profile_cache = {}

        self.entities = entity_manager.EntityManager(session=self)

        # A container for active plugins. This is done so that the interactive
        # console can see which plugins are active by simply command completing
        # on this object.
        self.plugins = PluginContainer(self)

        # When the session switches process context we store various things in
        # this cache, so we can restore the context quickly. The cache is
        # indexed by the current process_context which can be found from
        # session.GetParameter("process_context").
        self.context_cache = {}
        self._repository_managers = []

        # Store user configurable attributes here. These will be read/written to
        # the configuration file.
        self.state = Configuration(session=self)
        with self.state:
            self.state.Set("cache", Cache())

            for k, v in kwargs.items():
                self.state.Set(k, v)

    @property
    def repository_managers(self):
        """The IO managers that are used to fetch profiles from the profile
        repository.

        """
        if self._repository_managers:
            return self._repository_managers

        # The profile path is specified in search order.
        repository_path = (self.state.Get("repository_path") or
                           self.state.Get("profile_path") or [])

        for path in repository_path:
            self._repository_managers.append(
                (path, io_manager.Factory(path, session=self)))

        return self._repository_managers

    def __enter__(self):
        # Allow us to update the state context manager.
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

    @property
    def default_address_space(self):
        return self.GetParameter("default_address_space")

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

    def __getattr__(self, attr):
        """This will only get called if the attribute does not exist."""
        return obj.NoneObject("Attribute not set")

    def HasParameter(self, item):
        """Returns if the session has the specified parameter set.

        If False, a call to GetParameter() might trigger autodetection.
        """
        return (self.state.get(item) is not None or
                self.state.cache.get(item) is not None)

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
        result = self.state.get(item)

        # None in the state dict means that the cache is empty. This is
        # different from a NoneObject() returned (which represents a cacheable
        # failure).
        if result is None:
            result = self.state.cache.get(item)

        # The result is not in the cache. Is there a hook that can help?
        if result is None:
            result = self._RunParameterHook(item)

        # Note that the hook may return a NoneObject() which should be cached.
        if result == None:
            result = default

        return result

    def SetCache(self, item, value):
        """Store something in the cache."""
        self.state.cache.Set(item, value)

    def SetParameter(self, item, value):
        """Sets a session parameter.

        NOTE! This method should only be used for setting user provided data. It
        must not be used to set cached data - use SetCache() instead. Parameters
        set with this method are not cleared as part of session.Reset() and are
        copied to cloned sessions.
        """
        self.state.Set(item, value)

    def _RunParameterHook(self, name):

        """Launches the registered parameter hook for name."""
        for cls in kb.ParameterHook.classes.values():
            if cls.name == name and cls.is_active(self):
                hook = cls(session=self)
                result = hook.calculate()

                # Cache the output from the hook directly.
                self.state.cache[name] = result

                return result

    def _CorrectKWArgs(self, kwargs):
        """Normalize args to use _ instead of -.

        So we can pass them as valid python parameters.
        """
        result = {}
        for k, v in kwargs.iteritems():
            result[k.replace("-", "_")] = v
        return result

    def RunPlugin(self, plugin_obj, *pos_args, **kwargs):
        """Launch a plugin and its render() method automatically.

        We use the pager specified in session.GetParameter("pager").

        Args:
          plugin_obj: A string naming the plugin, or the plugin instance itself.
          *pos_args: Args passed to the plugin if it is not an instance.
          **kwargs: kwargs passed to the plugin if it is not an instance.
        """
        kwargs = self._CorrectKWArgs(kwargs)
        output = kwargs.pop("output", None)
        ui_renderer = kwargs.pop("renderer", None)

        # Do we need to redirect output?
        if output is not None:
            with self:
                # Do not lose the global output redirection.
                old_output = self.GetParameter("output") or None
                self.SetParameter("output", output)
                try:
                    return self._RunPlugin(plugin_obj, renderer=ui_renderer,
                                           *pos_args, **kwargs)
                finally:
                    self.SetParameter("output", old_output)

        else:
            return self._RunPlugin(plugin_obj, renderer=ui_renderer,
                                   *pos_args, **kwargs)

    def _GetPluginObj(self, plugin_obj, *pos_args, **kwargs):
        if isinstance(plugin_obj, basestring):
            plugin_name = plugin_obj

        elif utils.issubclass(plugin_obj, plugin.Command):
            plugin_name = plugin_obj.name
            plugin_cls = plugin_obj

        elif isinstance(plugin_obj, plugin.Command):
            return plugin_obj

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
                return plugin_obj.render(ui_renderer) or plugin_obj

        except plugin.InvalidArgs as e:
            logging.error("Invalid Args: %s", e)

        except plugin.PluginError as e:
            if isinstance(plugin_obj, plugin.Command):
                plugin_obj.error_status = str(e)
                ui_renderer.report_error(str(e))

        except (KeyboardInterrupt, plugin.Abort):
            ui_renderer.report_error("Aborted")
            self.report_progress("Aborted!\r\n", force=True)

        except Exception, e:
            error_status = traceback.format_exc()
            if isinstance(plugin_obj, plugin.Command):
                plugin_obj.error_status = error_status

            # Report the error to the renderer.
            ui_renderer.report_error(error_status)

            # If anything goes wrong, we break into a debugger here.
            if self.GetParameter("debug"):
                pdb.post_mortem(sys.exc_info()[2])

            raise

        finally:
            ui_renderer.flush()

        return plugin_obj

    def LoadProfile(self, name, use_cache=True):
        """Try to load a profile directly by its name.

        Args:

          name: A string which represents the canonical name for the profile. We
              ask all repositories in the repository_path to resolve this name
              into a profile.

        Returns:
          a Profile() instance or a NoneObject()

        """
        if not name:
            return obj.NoneObject("No filename")

        if isinstance(name, obj.Profile):
            return name

        # We only want to deal with unix paths.
        name = name.replace("\\", "/")

        try:
            if use_cache:
                cached_profile = self.profile_cache[name]
                if cached_profile:
                    return cached_profile

                else:
                    return obj.NoneObject(
                        "Unable to load profile %s from any repository." %
                        name)

        except KeyError:
            pass

        result = None

        try:
            # If the name is a path we try to open it directly:
            container = io_manager.DirectoryIOManager(os.path.dirname(name),
                                                      version=None)
            result = obj.Profile.LoadProfileFromData(
                container.GetData(os.path.basename(name)),
                self, name=name)
        except IOError:
            pass

        # Traverse the profile path until one works.
        if not result:
            # Add the last supported repository as the last fallback path.
            for path, manager in self.repository_managers:
                try:
                    # The inventory allows us to fail fetching the profile
                    # quickly - without making the round trip.
                    if not manager.CheckInventory(name):
                        logging.debug(
                            "Skipped profile %s from %s (Not in inventory)",
                            name, path)
                        continue

                    result = obj.Profile.LoadProfileFromData(
                        manager.GetData(name), self,
                        name=name)
                    logging.info(
                        "Loaded profile %s from %s", name, manager)

                    break

                except (IOError, KeyError) as e:
                    result = obj.NoneObject(e)
                    logging.debug("Could not find profile %s in %s: %s",
                                  name, path, e)

                    continue

        # Cache it for later. Note that this also caches failures so we do not
        # retry again.
        self.profile_cache[name] = result
        if result == None:
            return obj.NoneObject(
                "Unable to load profile %s from any repository." % name)

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
        res = self.GetParameter("profile_obj")
        return res

    @profile.setter
    def profile(self, value):
        # Clear the profile object. Next access to it will trigger profile
        # auto-detection.
        if value == None:
            self.state.cache.Set('profile_obj', value)

        elif isinstance(value, basestring):
            with self.state:
                self.state.Set('profile', value)

        elif isinstance(value, obj.Profile):
            self.state.cache.Set('profile_obj', value)
        else:
            raise AttributeError("Type %s not allowed for profile" % value)

    def clone(self, **kwargs):
        new_state = self.state.copy()
        # Remove the cache from the copy so we start with a fresh cache.
        new_state.pop("cache")

        # session_ids are automatically generated so we need to pop it.
        new_state.pop("session_id")

        session_id = self._new_session_id()
        old_session_name = new_state.pop("session_name")
        new_session_name = kwargs.pop(
            "session_name", kwargs.get(
                "filename", "%s (%s)" % (old_session_name, session_id)))
        new_session = self.__class__(
            session_name=new_session_name, session_id=session_id, **new_state)
        new_session.Reset()
        new_session.locals = self.locals

        # Now override all parameters as requested.
        with new_session:
            for k, v in kwargs.iteritems():
                new_session.SetParameter(k, v)
        return new_session


class JsonSerializableSession(Session):
    """A session which can serialize its state into a Json file."""

    # We only serialize the following session variables since they make this
    # session unique. When we unserialize we merge the other state variables
    # from this current session.
    SERIALIZABLE_STATE_PARAMETERS = [
        ("ept", u"IntParser"),
        ("profile", u"FileName"),
        ("filename", u"FileName"),
        ("pagefile", u"FileName"),
        ("session_name", u"String"),
        ("timezone", u"TimeZone"),
    ]

    def __eq__(self, other):
        if not isinstance(other, Session):
            return False

        for field, _ in self.SERIALIZABLE_STATE_PARAMETERS:
            if self.HasParameter(field):
                # We have this field but the other does not.
                if not other.HasParameter(field):
                    return False

                if self.GetParameter(field) != other.GetParameter(field):
                    return False

        return True

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
        self.state = Configuration(session=self, **decoder.Decode(data))

    def Serialize(self):
        encoder = json_renderer.JsonEncoder(
            session=self, renderer="JsonRenderer")

        data = encoder.Encode(self.state)
        return encoder.GetLexicon(), data


class DynamicNameSpace(dict):
    """A namespace which dynamically reflects the currently active plugins."""

    def __init__(self, session=None, **kwargs):
        if session is None:
            raise RuntimeError("Session must be given.")

        self.help_profile = None
        self.session = session

        super(DynamicNameSpace, self).__init__(
            session=session, plugins=session.plugins,
            **kwargs)

    def __iter__(self):
        res = set(super(DynamicNameSpace, self).__iter__())
        res.update(self["plugins"].__dir__())

        return iter(res)

    def __delitem__(self, item):
        try:
            super(DynamicNameSpace, self).__delitem__(item)
        except KeyError:
            pass

    def keys(self):
        return list(self)

    def __getitem__(self, item):
        try:
            return super(DynamicNameSpace, self).__getitem__(item)
        except KeyError:
            if getattr(self["session"].plugins, item):
                return self._prepare_runner(item)

            raise KeyError(item)

    def get(self, item, default=None):
        try:
            return self[item]
        except KeyError:
            return default

    def _prepare_runner(self, name):
        """Prepare a runner to run the given plugin."""
        if self.help_profile is None:
            self.help_profile = self.session.LoadProfile("help_doc")

        doc = ""
        plugin_cls = self.session.plugins.GetPluginClass(name)
        default_args = ""
        if plugin_cls:
            default_args, doc = "", ""
            default_args = self.help_profile.ParametersForPlugin(
                plugin_cls.__name__)
            doc = self.help_profile.DocsForPlugin(plugin_cls.__name__)

        # Create a runner for this plugin and set its documentation.
        runner = obj.Curry(
            self["session"].RunPlugin, name, default_arguments=default_args)

        runner.__doc__ = doc

        return runner


class InteractiveSession(JsonSerializableSession):
    """The session allows for storing of arbitrary values and configuration.

    This session contains a lot of convenience features which are useful for
    interactive use.
    """

    # A list of tuples (session_id, session) sorted by session id. This list is
    # shared by all session instances! TODO: Refactor into a session group.
    session_list = []

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
        # When this session was created.
        self._start_time = time.time()

        # These keep track of the last run plugin.
        self._last_plugin = None

        # Fill the session with helpful defaults.
        self.pager = obj.NoneObject("Set this to your favourite pager.")

        # Set the session name
        self.session_name = kwargs.pop("session_name", u"Default session")
        super(InteractiveSession, self).__init__()

        # Prepare the local namespace for the interactive session.
        self.locals = DynamicNameSpace(
            session=self,

            # Prepopulate the namespace with our most important modules.
            profile=self.profile,
            v=self.v,

            # Some useful modules which should be available always.
            sys=sys, os=os,

            # A list of sessions.
            session_list=self.session_list,

            # Pass additional environment.
            **(env or {})
            )

        with self.state:
            self.state.Set("session_list", self.session_list)
            self.state.Set("session_name", self.session_name)
            self.state.Set("session_id", self._new_session_id())

        # Configure the session from the config file and kwargs.
        if use_config_file:
            with self.state:
                config.MergeConfigOptions(self.state)

            with self.state:
                for k, v in kwargs.items():
                    self.state.Set(k, v)

    @property
    def session_id(self):
        return self.GetParameter("session_id")

    def find_session(self, session_id):
        for session in self.session_list:
            if session.session_id == session_id:
                return session

        return None

    def _new_session_id(self):
        new_sid = 1
        for session in InteractiveSession.session_list:
            if new_sid <= session.session_id:
                new_sid = session.session_id + 1

        return new_sid

    def RunPlugin(self, *args, **kwargs):
        self.last = super(InteractiveSession, self).RunPlugin(*args, **kwargs)
        return self.last

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

    def add_session(self, **kwargs):
        """Creates a new session and adds it to the list.

        Returns:
          the new session.
        """
        session_id = kwargs["session_id"] = self._new_session_id()
        if "session_name" not in kwargs:
            # Make a unique session name.
            kwargs["session_name"] = u"%s (%s)" % (
                kwargs.get("filename", session_id), session_id)

        new_session = self.__class__(**kwargs)
        new_session.locals = self.locals

        self.session_list.append(new_session)
        self.session_list.sort(key=lambda x: x.session_id)

        return new_session
