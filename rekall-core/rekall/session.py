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

import logging
import os
import pdb
import sys
import time
import traceback
import weakref

from rekall import cache
from rekall import config
from rekall import constants
from rekall import io_manager
from rekall import kb
from rekall import obj
from rekall import plugin
from rekall import registry
from rekall import utils

from rekall.ui import renderer


config.DeclareOption(
    "--repository_path", default=[], type="ArrayStringParser",
    help="Path to search for profiles. This can take "
    "any form supported by the IO Manager (e.g. zip files, "
    "directories, URLs etc)")

config.DeclareOption("-f", "--filename",
                     help="The raw image to load.")

config.DeclareOption(
    "--buffer_size", default=20 * 1024 * 1024,
    type="IntParser",
    help="The maximum size of buffers we are allowed to read. "
    "This is used to control Rekall memory usage.")

config.DeclareOption(
    "--output", default=None,
    help="If specified we write output to this file.")

config.DeclareOption(
    "--max_collector_cost", default=4, type="IntParser",
    help="If specified, collectors with higher cost will not be used.")

config.DeclareOption(
    "--home", default=None,
    help="An alternative home directory path. If not set we use $HOME.")

config.DeclareOption(
    "--logging_format",
    default="%(asctime)s:%(levelname)s:%(name)s:%(message)s",
    help="The format string to pass to the logging module.")

config.DeclareOption(
    "--performance", default="normal", type="Choices",
    choices=["normal", "fast", "thorough"],
    help="Tune Rekall's choice of algorithms, depending on performance "
    "priority.")

LIVE_MODES = ["API", "Memory"]

config.DeclareOption(
    "--live", default=None, type="Choice", required=False,
    choices=LIVE_MODES, help="Enable live memory analysis.")


class RecursiveHookException(RuntimeError):
    """Raised when a hook is invoked recursively."""


class PluginRunner(obj.Curry):
    """A runner for a specific plugin."""

    def __init__(self, session, plugin_name):
        super(PluginRunner, self).__init__(session.RunPlugin, plugin_name)
        self.plugin_name = plugin_name
        self.session = session

    def Metadata(self):
        """Return metadata about this plugin."""
        plugin_class = getattr(   # pylint: disable=protected-access
            self.session.plugins, self.plugin_name)._target
        return config.CommandMetadata(plugin_class).Metadata()


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


class PluginRunnerContainer(PluginContainer):
    """Like a PluginContainer but returns plugin runners."""

    def __getattr__(self, name):
        plugin_cls = self.GetPluginClass(name)
        if plugin_cls == None:
            return plugin_cls

        return PluginRunner(self.session, name)


class Configuration(utils.AttributeDict):
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

    def _set_live(self, live, _):
        if live is not None and not self.live:
            if isinstance(live, basestring):
                live = [live]

            # Default is to use Memory analysis.
            if len(live) == 0:
                mode = "Memory"
            elif len(live) == 1:
                mode = live[0]
            else:
                raise RuntimeError(
                    "--live parameter should specify only one mode.")

            live_plugin = self.session.plugins.live(mode=mode)
            live_plugin.live()

            # When the session is destroyed, close the live plugin.
            self.session.register_flush_hook(self, live_plugin.close)

        return live

    def _set_home(self, home, _):
        """Ensure the home directory is valid."""
        if home:
            home = os.path.abspath(home)
            if not os.path.isdir(home):
                raise ValueError("Home directory must be a directory.")
        else:
            home = config.GetHomeDir(self.session)

        # We must update the environment so things like os.path.expandvars
        # work.
        os.environ["HOME"] = home
        return home

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
            # Clear the existing profile which will trigger profile
            # autodetection on the new image.
            del self['profile']
            self['filename'] = filename

        return filename

    def _set_autodetect_build_local_tracked(self, tracked, _):
        """Update the tracked modules.

        When someone updates the build local tracked parameter we need to remove
        them from all the address resolver caches.
        """
        # Clear all profile caches in address resolver contexts.
        for context in self.session.context_cache.values():
            context.reset()

        return set(tracked)

    def _set_repository_path(self, profile_path, _):
        # Flush the profile cache if we change the profile path.
        self.session.profile_cache = {}

        return profile_path

    def _set_profile(self, profile, _):
        """This is triggered when someone explicitly sets the profile.

        We force load the profile and avoid autodetection.
        """
        profile_obj = self.session.LoadProfile(profile)
        if profile_obj:
            self.session.SetCache("profile_obj", profile_obj,
                                  volatile=False)

        return profile

    def _set_logging_level(self, level, _):
        if isinstance(level, basestring):
            level = getattr(logging, level.upper(), logging.INFO)

        if level == None:
            return

        self.session.logging.debug("Logging level set to %s", level)
        self.session.logging.setLevel(int(level))
        if isinstance(self.session, InteractiveSession):
            # Also set the root logging level, to reflect it in the console.
            logging.getLogger().setLevel(int(level))

        # Create subloggers and suppress their logging level.
        for log_domain in constants.LOG_DOMAINS:
            logger = self.session.logging.getChild(log_domain)
            logger.setLevel(logging.WARNING)

    def _set_log_domain(self, domains, _):
        for domain in domains:
            logger = self.session.logging.getChild(domain)
            logger.setLevel(logging.DEBUG)

    def _set_logging_format(self, logging_format, _):
        formatter = logging.Formatter(fmt=logging_format)

        # Set the logging format on the console
        root_logger = logging.getLogger()
        if not root_logger.handlers:
            logging.basicConfig(format=logging_format)
        else:
            for handler in root_logger.handlers:
                handler.setFormatter(formatter)

        # Now set the format of our custom handler(s).
        for handler in self.session.logging.handlers:
            handler.setFormatter(formatter)

    def _set_ept(self, ept, _):
        self.session.Reset()
        self["ept"] = ept
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

    def __str__(self):
        """Print the contents somewhat concisely."""
        result = []
        for k, v in self.iteritems():
            if isinstance(v, obj.BaseObject):
                v = repr(v)

            value = "\n  ".join(str(v).splitlines())
            if len(value) > 100:
                value = "%s ..." % value[:100]

            result.append("  %s = %s" % (k, value))

        return "{\n" + "\n".join(sorted(result)) + "\n}"


class ProgressDispatcher(object):
    """An object to manage progress calls.

    Since Rekall must be usable as a library it can not block for too
    long. Rekall makes continuous reports of its progress to the
    ProgressDispatcher, which then further dispatches them to other
    callbacks. This allows users of the Rekall library to be aware of how
    analysis is progressing. (e.g. to report it in a GUI).
    """

    def __init__(self):
        self.callbacks = {}

    def Register(self, key, callback):
        self.callbacks[key] = callback

    def UnRegister(self, key):
        self.callbacks.pop(key, 0)

    def Broadcast(self, message, *args, **kwargs):
        for handler in self.callbacks.values():
            handler(message, *args, **kwargs)


class HoardingLogHandler(logging.Handler):
    """A logging LogHandler that stores messages as long as a renderer hasn't
    been assigned to it. Used to keep all messages that happen in Rekall before
    a plugin has been initialized or run at all, to later send them to a
    renderer.
    """

    def __init__(self, *args, **kwargs):
        self.logrecord_buffer = []
        self.renderer = None
        super(HoardingLogHandler, self).__init__(*args, **kwargs)

    def emit(self, record):
        """Deliver a message if a renderer is defined or store it, otherwise."""
        if not self.renderer:
            self.logrecord_buffer.append(record)
        else:
            self.renderer.Log(record)

    def SetRenderer(self, renderer_obj):
        """Sets the renderer so messages can be delivered."""
        self.renderer = renderer_obj
        self.Flush()

    def Flush(self):
        """Sends all stored messages to the renderer."""
        if self.renderer:
            for log_record in self.logrecord_buffer:
                self.renderer.Log(log_record)

            self.logrecord_buffer = []


class Session(object):
    """Base session.

    This session contains the bare minimum to use rekall.
    """

    # We only serialize the following session variables since they make this
    # session unique. When we unserialize we merge the other state variables
    # from this current session.
    #
    # TODO: This is, for the moment, necessary to support the web UI. Come up
    # with a better way to represent or generate this list.
    SERIALIZABLE_STATE_PARAMETERS = [
        ("ept", u"IntParser"),
        ("profile", u"FileName"),
        ("filename", u"FileName"),
        ("pagefile", u"FileName"),
        ("session_name", u"String"),
        ("timezone", u"TimeZone"),
    ]

    __metaclass__ = registry.MetaclassRegistry

    # The currently active address resolver.
    _address_resolver = None

    # Each session has a unique session id (within this process). The ID is only
    # unique among the sessions currently active.
    session_id = 0

    # Privileged sessions are allowed to run dangerous plugins.
    privileged = False

    def __init__(self, **kwargs):
        self.progress = ProgressDispatcher()

        # Cache the profiles we get from LoadProfile() below.
        self.profile_cache = {}

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
        self.cache = cache.Factory(self, "memory")
        with self.state:
            for k, v in kwargs.items():
                self.state.Set(k, v)

        # We use this logger if provided.
        self.logger = kwargs.pop("logger", None)
        self._logger = None

        # Make this session id unique.
        Session.session_id += 1

        # At the start we haven't run any plugin.
        self.last = None

        # Locks for running hooks.
        self._hook_locks = set()

        # Hooks that will be called when we get flushed.
        self._flush_hooks = []

        self.renderers = []

    @utils.safe_property
    def logging(self):
        if self.logger is not None:
            return self.logger

        logger_name = u"rekall.%s" % self.session_id
        if self._logger is None or self._logger.name != logger_name:
            # Set up a logging object. All rekall logging must be done
            # through the session's logger.
            self._logger = logging.getLogger(logger_name)

            # A special log handler that hoards all messages until there's a
            # renderer that can transport them.
            self._log_handler = HoardingLogHandler()

            # Since the logger is a global it must not hold a permanent
            # reference to the HoardingLogHandler, otherwise we may never be
            # collected.
            def Remove(_, l=self._log_handler):
                l.handlers = []

            self._logger.addHandler(weakref.proxy(
                self._log_handler, Remove))

        return self._logger

    @utils.safe_property
    def volatile(self):
        return (self.physical_address_space and
                self.physical_address_space.volatile)

    @utils.safe_property
    def repository_managers(self):
        """The IO managers that are used to fetch profiles from the profile
        repository.

        """
        if self._repository_managers:
            return self._repository_managers

        # The profile path is specified in search order.
        repository_path = (self.GetParameter("repository_path") or
                           self.GetParameter("profile_path") or [])

        for path in repository_path:
            # TODO(scudette): remove this hack for 1.6 release.  Github has
            # changed their static URL access. If the user is using an old URL
            # we warn and correct it.
            if path in constants.OLD_DEPRECATED_URLS:
                self.logging.warn(
                    "Rekall's profile repository is pointing to deprecated URL "
                    "(%s). Please update your ~/.rekallrc file.", path)
                path = constants.PROFILE_REPOSITORIES[0]

            try:
                self._repository_managers.append(
                    (path, io_manager.Factory(path, session=self)))
            except ValueError:
                pass

        if not self._repository_managers:
            self.logging.warn(
                "No usable repositories were found. "
                "Rekall Will attempt to use the local cache. This is likely "
                "to fail if profiles are missing locally!")
            self._repository_managers = [
                (None, io_manager.DirectoryIOManager(
                    urn=cache.GetCacheDir(self), session=self))]

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
        self.kernel_address_space = None

        # For volatile sessions we use a timed cache (which expires after a
        # short time).
        cache_type = self.GetParameter("cache", "memory")
        if self.volatile:
            cache_type = "timed"

        if self.cache:
            self.remove_flush_hook(self.cache)

        self.cache = cache.Factory(self, cache_type)
        if self.physical_address_space:
            self.physical_address_space.ConfigureSession(self)

        # Fix up the completer. This is sometimes required after the debugger
        # steals readline focus. Typing session.Reset() fixes things again.
        self.shell.init_completer()

    @utils.safe_property
    def default_address_space(self):
        return self.GetParameter("default_address_space")

    @utils.safe_property
    def address_resolver(self):
        """A convenience accessor for the address resolver implementation.

        Note that the correct address resolver implementation depends on the
        profile. For example, windows has its own address resolver, while Linux
        and OSX have a different one.
        """
        # Get the current process context.
        current_context = (self.GetParameter("process_context").obj_offset or
                           "Kernel")

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
                self.cache.Get(item) is not None)

    def GetParameter(self, item, default=obj.NoneObject(), cached=True):
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
        if result is not None:
            return result

        # None in the state dict means that the cache is empty. This is
        # different from a NoneObject() returned (which represents a cacheable
        # failure).
        if cached:
            result = self.cache.Get(item)
            if result is not None:
                return result

        # We don't have or didn't look in the cache for the result. See if we
        # can get if from a hook.
        try:
            result = self._RunParameterHook(item)
            if result is not None:
                return result
        except RecursiveHookException:
            pass

        return default

    def SetCache(self, item, value, volatile=True):
        """Store something in the cache."""
        self.cache.Set(item, value, volatile=volatile)

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
                if name in self._hook_locks:
                    # This should never happen! If it does then this will block
                    # in a loop so we fail hard.
                    raise RecursiveHookException(
                        "Trying to invoke hook %s recursively!" % name)

                try:
                    self._hook_locks.add(name)
                    hook = cls(session=self)
                    result = hook.calculate()

                    # Cache the output from the hook directly.
                    self.SetCache(name, result, volatile=hook.volatile)
                finally:
                    self._hook_locks.remove(name)

                return result

    def _CorrectKWArgs(self, kwargs):
        """Normalize args to use _ instead of -.

        So we can pass them as valid python parameters.
        """
        result = {}
        for k, v in kwargs.iteritems():
            result[k.replace("-", "_")] = v
        return result

    def RunPlugin(self, plugin_obj, *args, **kwargs):
        """Launch a plugin and its render() method automatically.

        We use the pager specified in session.GetParameter("pager").

        Args:
          plugin_obj: A string naming the plugin, or the plugin instance itself.
          *pos_args: Args passed to the plugin if it is not an instance.
          **kwargs: kwargs passed to the plugin if it is not an instance.
        """
        kwargs = self._CorrectKWArgs(kwargs)
        output = kwargs.pop("output", self.GetParameter("output"))
        ui_renderer = kwargs.pop("format", None)
        result = None

        if ui_renderer is None:
            ui_renderer = self.GetRenderer(output=output)

        self.renderers.append(ui_renderer)

        # Set the renderer so we can transport log messages.
        self._log_handler.SetRenderer(ui_renderer)

        try:
            plugin_name = self._GetPluginName(plugin_obj)
        except Exception as e:
            raise ValueError(
                "Invalid plugin_obj parameter (%s)." % repr(plugin))

        # On multiple calls to RunPlugin, we need to make sure the
        # HoardingLogHandler doesn't send messages to the wrong renderer.
        # We reset the renderer and make it hoard messages until we have the
        # new one.
        self.logging.debug(
            u"Running plugin (%s) with args (%s) kwargs (%s)",
            plugin_name, args, utils.SmartUnicode(kwargs)[:1000])

        with ui_renderer.start(plugin_name=plugin_name, kwargs=kwargs):
            try:
                original_plugin_obj = plugin_obj
                plugin_obj = self._GetPluginObj(plugin_obj, *args, **kwargs)
                if not plugin_obj:
                    raise ValueError(
                        "Invalid plugin: %s" % original_plugin_obj)
                result = plugin_obj.render(ui_renderer) or plugin_obj
                self.last = plugin_obj
            except (Exception, KeyboardInterrupt) as e:
                self._HandleRunPluginException(ui_renderer, e)

            finally:
                self.renderers.pop(-1)

        # At this point, the ui_renderer will have flushed all data.
        # Further logging will be lost.
        return result

    def _HandleRunPluginException(self, ui_renderer, e):
        """Handle exceptions thrown while trying to run a plugin."""
        _ = ui_renderer, e
        # This method is called from exception handlers.
        raise  # pylint: disable=misplaced-bare-raise

    def _GetPluginName(self, plugin_obj):
        """Extract the name from the plugin object."""
        if isinstance(plugin_obj, basestring):
            return plugin_obj

        elif utils.issubclass(plugin_obj, plugin.Command):
            return plugin_obj.name

        elif isinstance(plugin_obj, plugin.Command):
            return plugin_obj.name

    def _GetPluginObj(self, plugin_obj, *args, **kwargs):
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
                self.logging.error(
                    "Plugin %s is not active. Is it supported with "
                    "this profile?", plugin_name)
                return

        # Instantiate the plugin object.
        kwargs["session"] = self
        return plugin_cls(*args, **kwargs)

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
                                                      version=None,
                                                      session=self)
            data = container.GetData(os.path.basename(name))
            if data == None:
                raise IOError("Not found.")

            result = obj.Profile.LoadProfileFromData(data, self, name=name)
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
                        self.logging.debug(
                            "Skipped profile %s from %s (Not in inventory)",
                            name, path)
                        continue

                    now = time.time()
                    result = obj.Profile.LoadProfileFromData(
                        manager.GetData(name), session=self, name=name)
                    if result:
                        self.logging.info(
                            "Loaded profile %s from %s (in %s sec)",
                            name, manager, time.time() - now)
                        break

                except (IOError, KeyError) as e:
                    result = obj.NoneObject(e)
                    self.logging.debug("Could not find profile %s in %s: %s",
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

    def GetRenderer(self, output=None):
        """Get a renderer for this session.

        If a renderer is currently active we just reuse it, otherwise we
        instantiate the renderer specified in self.GetParameter("format").
        """
        # Reuse the current renderer.
        if self.renderers and output is None:
            return self.renderers[-1]

        ui_renderer = self.GetParameter("format", "text")
        if isinstance(ui_renderer, basestring):
            ui_renderer_cls = renderer.BaseRenderer.ImplementationByName(
                ui_renderer)
            ui_renderer = ui_renderer_cls(session=self, output=output)

        return ui_renderer

    @utils.safe_property
    def physical_address_space(self):
        res = self.GetParameter("physical_address_space", None)
        return res

    @physical_address_space.setter
    def physical_address_space(self, value):
        # The physical_address_space is not part of the cache because
        # it needs to be set first before we know which cache
        # fingerprint to use (getting the fingerprint depends on the
        # physical_address_space).
        self.SetParameter("physical_address_space", value)
        self.Reset()

        # Ask the physical_address_space to configure this session.
        if value:
            value.ConfigureSession(self)

    @utils.safe_property
    def profile(self):
        # If a process context is specified, we use the profile from the process
        # context.
        process_context = self.GetParameter("process_context").obj_profile
        if process_context != None:
            return process_context

        res = self.GetParameter("profile_obj")
        return res

    @profile.setter
    def profile(self, value):
        # Clear the profile object. Next access to it will trigger profile
        # auto-detection.
        if value == None:
            self.SetCache('profile_obj', value, volatile=False)

        elif isinstance(value, basestring):
            with self.state:
                self.state.Set('profile', value)

        elif isinstance(value, obj.Profile):
            self.SetCache('profile_obj', value, volatile=False)
            self.SetCache("profile", value.name, volatile=False)
        else:
            raise AttributeError("Type %s not allowed for profile" % value)

    def clone(self, **kwargs):
        new_state = self.state.copy()
        # Remove the cache from the copy so we start with a fresh cache.
        new_state.pop("cache", None)

        # session_ids are automatically generated so we need to pop it.
        new_state.pop("session_id", None)

        session_id = self._new_session_id()
        old_session_name = new_state.pop("session_name", None)
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

    def register_flush_hook(self, owner, hook, args=()):
        """This hook will run when the session is closed."""
        self._flush_hooks.append((owner, hook, args))

    def remove_flush_hook(self, owner):
        """Removes the flush hooks set by the owner.

        Returns the hooks so they can be called if needed.
        """
        owners_hooks = []
        flush_hooks = []
        for x in self._flush_hooks:
            if x[0] is owner:
                owners_hooks.append(x)
            else:
                flush_hooks.append(x)
        self._flush_hooks = flush_hooks

        return owners_hooks

    def Flush(self):
        """Destroy this session.

        This should be called when the session is destroyed.
        """
        for _, hook, args in self._flush_hooks:
            hook(*args)


class DynamicNameSpace(dict):
    """A namespace which dynamically reflects the currently active plugins.

    This forms the global namespace inside the ipython interpreter shell. There
    are some special variables prepopulated:

    - plugins: A PluginRunnerContainer that users can use to see which plugins
      are active.

    - session: A reference to the current session.
    """

    def __init__(self, session=None, **kwargs):
        if session is None:
            raise RuntimeError("Session must be given.")

        self.help_profile = None
        self.session = session

        super(DynamicNameSpace, self).__init__(
            session=session,
            plugins=PluginRunnerContainer(session),
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
        # Create a runner for this plugin.
        return PluginRunner(self["session"], name)


class InteractiveSession(Session):
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
                config.MergeConfigOptions(self.state, self)

            with self.state:
                for k, v in kwargs.items():
                    self.state.Set(k, v)

    @utils.safe_property
    def session_id(self):
        return self.GetParameter("session_id", default=Session.session_id)

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

    def _HandleRunPluginException(self, ui_renderer, e):
        """Handle all exceptions thrown by logging to the console."""

        if isinstance(e, plugin.InvalidArgs):
            self.logging.fatal("Invalid Args: %s" % e)

        elif isinstance(e, plugin.PluginError):
            self.logging.fatal(str(e))

        elif isinstance(e, KeyboardInterrupt) or isinstance(e, plugin.Abort):
            logging.error("Aborted\r\n")

        else:
            error_status = traceback.format_exc()

            # Report the error to the renderer.
            self.logging.fatal(error_status)

            # If anything goes wrong, we break into a debugger here.
            if self.GetParameter("debug"):
                pdb.post_mortem(sys.exc_info()[2])

            # This method is called from the exception handler - this bare raise
            # will preserve backtraces.
            raise  # pylint: disable=misplaced-bare-raise

    def v(self):
        """Re-execute the previous command."""
        if self.last:
            self.RunPlugin(self.last)

    def lister(self, arg):
        for x in arg:
            self.printer(x)

    def __str__(self):
        return self.__unicode__()

    def __unicode__(self):
        result = u"""Rekall Memory Forensics session Started on %s.

Config:
%s

Cache (%r):
%s
""" % (time.ctime(self._start_time), self.state, self.cache, self.cache)
        return result

    def __dir__(self):
        items = self.__dict__.keys() + dir(self.__class__)

        return [x for x in items if not x.startswith("_")]

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

        new_session = self.__class__()
        new_session.locals = self.locals
        # pylint: disable=protected-access
        new_session._repository_managers = self._repository_managers
        new_session.profile_cache = self.profile_cache

        with new_session:
            for k, v in kwargs.iteritems():
                new_session.SetParameter(k, v)

        self.session_list.append(new_session)
        self.session_list.sort(key=lambda x: x.session_id)

        return new_session
