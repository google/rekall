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

"""This module implements the Rekall renderer API.

Rekall has a pluggable rendering system. At the top level we have renderers
which are reponsible for converting the output of plugins into something usable
for the user (whatever that means).

A Rekall plugin uses the renderer to produce output by providing it with a bunch
of objects which are derived from the analysis stage. The renderer is then
responsible for rendering these special objects using pluggable
ObjectRenderer() classes.

1. The framework creates a BaseRenderer implementation (e.g. TextRenderer or
   JsonRenderer)

2. This is passed to a plugin's render() method.

3. The Plugin provides various objects to the renderer via its table_row(),
   format() etc methods.

4. The renderer than uses specialized ObjectRenderer() instances to render the
   objects that the plugin gave it.

For example, by default the renderer used is an instance of TextRenderer. The
PSList() plugin in its render() method, calls renderer.table_row() passing a
WinFileTime() instance as the "Create Time" cell of the table.

The TextRenderer plugin aims to layout the output into the text terminal. For
this to happen it must convert the WinFileTime() instance to a rendering
primitive, specific to the TextRenderer - in this case a Cell() instance. This
conversion is done using an ObjectRenderer instance.

The TextRenderer therefore selects an ObjectRenderer instance based on two
criteria:

- The ObjectRenderer claims to support the WinFileTime() object, or any of its
  base classes in order (using the ObjectRenderer.renders_type attribute).

- The ObjectRenderer claims to support the specific renderer
  (i.e. TextRenderer) using its `renderers` attribute.

The TextRenderer searches for an ObjectRenderer() by traversing the
WinFileTime's __mro__ (i.e. inheritance hierarchy) for a plugin capable of
rendering it. This essentially goes from most specialized to the least
specialized renderer:

- WinFileTime
- UnixTimeStamp   <-- Specialized object renderer for unix times.
- NativeType
- BaseObject
- object          <--- Generic renderer for all objects.

Once a renderer is found, it is used to output the cell value.

## NOTES

1. A specialized object renderer is written specifically for the renderer. This
   means that it is possible to have a specialized _EPROCESS object renderer for
   TextRenderer but when using the JsonRenderer a more general renderer may be
   chosen (say at the BaseObject level).

2. The ObjectRenderer.render_row() method actually returns something which makes
   sense to the supported renderer. There is no API specification for the return
   value. For example the TextRenderer needs a Cell instance but the
   JsonRenderer requires just a dict. Since ObjectRenderer instances are only
   used within the renderer they only need to cooperate with the renderer class
   they support.
"""
import collections
import gc
import inspect
import logging
import time

from rekall import config
from rekall import constants
from rekall import registry
from rekall import utils


config.DeclareOption(
    "-v", "--verbose", default=False, type="Boolean",
    help="Set logging to debug level.", group="Output control")

config.DeclareOption(
    "-q", "--quiet", default=False, type="Boolean",
    help="Turn off logging to stderr.", group="Output control")

config.DeclareOption(
    "--debug", default=False, type="Boolean",
    help="If set we break into the debugger on error conditions.")

config.DeclareOption(
    "--output_style", type="Choices", default="concise",
    choices=["concise", "full"],
    help="How much information to show. Default is 'concise'.")

config.DeclareOption(
    "--logging_level", type="Choices", default="WARNING",
    choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
    help="The default logging level.")

config.DeclareOption(
    "--log_domain", type="ChoiceArray", default=[],
    choices=constants.LOG_DOMAINS,
    help="Add debug logging to these components.")


# A cache to map a tuple (mro, renderer) to the corresponding object renderer.
MRO_RENDERER_CACHE = utils.FastStore(100, lock=True)

# A cache to map a class to its reduced MRO list. Do not hold class references
# in this cache as these capture closure variables via the Curry() classes on
# the property methods.
MRO_CACHE = utils.FastStore(100, lock=True)


class ObjectRenderer(object):
    """Baseclass for all TestRenderer object renderers."""

    # Fall back renderer for all objects. This can also be a list or tuple of
    # all types rendered by this renderer.
    renders_type = "object"

    # These are the renderers supported by this object renderer.
    renderers = []

    __metaclass__ = registry.MetaclassRegistry

    # A cache of Renderer, MRO mappings.
    _RENDERER_CACHE = None

    def __init__(self, renderer=None, session=None, **options):
        if not isinstance(renderer, BaseRenderer):
            raise RuntimeError("Renderer object must be provided. Got %r."
                               % renderer)

        self.renderer = renderer
        self.session = session

        self.options = options
        if self.session:
            self.output_style = self.session.GetParameter("output_style")
        else:
            self.output_style = None

    @staticmethod
    def get_mro(item):
        """Return the MRO of an item."""
        if not inspect.isclass(item):
            item = item.__class__

        try:
            return MRO_CACHE.Get(item.__name__)
        except KeyError:
            # Remove duplicated class names from the MRO (The current
            # implementation uses the flat class name to select the
            # ObjectRenderer so we can get duplicates but they dont matter).
            result = tuple(collections.OrderedDict.fromkeys(
                [unicode(x.__name__) for x in item.__mro__]))

            MRO_CACHE.Put(item.__name__, result)
            return result

    @classmethod
    def ByName(cls, name, renderer):
        """A constructor for an ObjectRenderer by name."""
        cls._BuildRendererCache()

        if not isinstance(renderer, basestring):
            renderer = renderer.__class__.__name__

        # Find the object renderer which works for this name.
        return cls._RENDERER_CACHE.get((name, renderer))

    @classmethod
    def FromMRO(cls, mro, renderer):
        """Get the best object renderer class from the MRO."""
        try:
            return MRO_RENDERER_CACHE[(mro, renderer)]
        except KeyError:
            cls._BuildRendererCache()

            if not isinstance(renderer, basestring):
                renderer = renderer.__class__.__name__

            # MRO is the list of object inheritance for each type. For example:
            # FileAddressSpace,FDAddressSpace,BaseAddressSpace.  We try to match
            # the object renderer from most specific to least specific (or more
            # general).
            for class_name in mro.split(":"):
                object_renderer_cls = cls._RENDERER_CACHE.get(
                    (class_name, renderer))

                if object_renderer_cls:
                    MRO_RENDERER_CACHE.Put((mro, renderer), object_renderer_cls)
                    return object_renderer_cls

    @classmethod
    def _BuildRendererCache(cls):
        # Build the cache if needed.
        if cls._RENDERER_CACHE is None:
            # Do this in a thread safe manner.
            result = {}
            for object_renderer_cls in cls.classes.values():
                for impl_renderer in object_renderer_cls.renderers:
                    render_types = object_renderer_cls.renders_type
                    if not isinstance(render_types, (list, tuple)):
                        render_types = (render_types,)

                    for render_type in render_types:
                        key = (render_type, impl_renderer)
                        if key in result:
                            raise RuntimeError(
                                "Multiple renderer implementations for class "
                                "%s: %s, %s" % (key, object_renderer_cls,
                                                result[key]))

                        result[key] = object_renderer_cls

            cls._RENDERER_CACHE = result

    @classmethod
    def ForTarget(cls, target, renderer):
        """Get the best ObjectRenderer to encode this target.

        ObjectRenderer instances are chosen based on both the taget and the
        renderer they implement.

        Args:
          taget: The target object to render. We walk the MRO to select the best
            renderer. This is a python object to be rendered.

          renderer: The renderer that will be used. This can be a string
             (e.g. "TextRenderer") or a renderer instance.

        Returns:
          An ObjectRenderer class which is best suited for rendering the target.
        """
        return cls.ForType(type(target), renderer)

    @classmethod
    def ForType(cls, target_type, renderer):
        """Get the best ObjectRenderer to encode this target type.

        ObjectRenderer instances are chosen based on both the taget and the
        renderer they implement.

        Args:
          taget_type: Type of the rendered object. We walk the MRO to select
            the best renderer.

          renderer: The renderer that will be used. This can be a string
             (e.g. "TextRenderer") or a renderer instance.

        Returns:
          An ObjectRenderer class which is best suited for rendering the target.
        """
        cls._BuildRendererCache()

        if not isinstance(renderer, basestring):
            renderer = renderer.__class__.__name__

        # Search for a handler which supports both the renderer and the object
        # type.
        for mro_cls in cls.get_mro(target_type):
            handler = cls._RENDERER_CACHE.get((mro_cls, renderer))
            if handler:
                return handler

    @classmethod
    def cache_key(cls, item):
        """Return a suitable cache key."""
        return repr(item)

    def DelegateObjectRenderer(self, item):
        """Create an object renderer for an item based on this object renderer.

        This is useful when delegating to render something else.
        """
        renderer_cls = self.ForTarget(item, self.renderer)
        return renderer_cls(session=self.session, renderer=self.renderer,
                            **self.options)

    def render_header(self, name=None, **options):
        """This should be overloaded to return the header Cell.

        Note that typically the same ObjectRenderer instance will be used to
        render all Cells in the same column.

        Args:
          name: The name of the Column.
          options: The options of the column (i.e. the dict which defines the
            column).

        Return:
          A Cell instance containing the formatted Column header.
        """

    def render_row(self, target, **options):
        """Render the target suitably.

        Args:
          target: The object to be rendered.

          options: A dict containing rendering options. The options are created
            from the column options, overriden by the row options and finally
            the cell options.  It is ok for an instance to ignore some or all of
            the options. Some options only make sense in certain Renderer
            contexts.

        Returns:
          A Cell instance containing the rendering of target.
        """


class BaseTable(object):
    """Renderers contain tables."""

    def __init__(self, session=None, renderer=None, columns=None, **options):
        self.session = session
        self.renderer = renderer
        self.options = options
        self.column_specs = []

        if not isinstance(renderer, BaseRenderer):
            raise TypeError("Renderer object must be supplied. Got %r."
                            % renderer)

        # For now support the legacy column specification and normalized to a
        # column_spec dict.
        for column in columns or []:
            # Old style column specification are a tuple. The new way is a dict
            # which is more expressive but more verbose.
            if isinstance(column, (tuple, list)):
                column = dict(name=column[0],
                              formatstring=column[2])

            self.column_specs.append(column)

    def render_row(self, *row, **options):
        """Render the row suitably."""

    def flush(self):
        pass


class BaseRenderer(object):
    """All renderers inherit from this.

    This class defines the only public interface for the rendering system. This
    is the API which should be used by Rekall plugins to render the
    output. Derived classes can add additional methods, but these should not be
    directly used by the plugins - otherwise plugins will fail when being
    rendered with different renderer implementations.
    """

    __metaclass__ = registry.MetaclassRegistry

    # The user friendly name of this renderer. This is used for selection from
    # command line etc.
    name = None

    last_spin_time = 0
    last_gc_time = 0
    progress_interval = 0.2

    # This is used to ensure that renderers are always called as context
    # managers. This guarantees we call start() and end() automatically.
    _started = False

    # Currently used table.
    table = None

    table_class = BaseTable

    def __init__(self, session=None):
        self.session = session

    def __enter__(self):
        self._started = True
        return self

    def __exit__(self, exc_type, exc_value, trace):
        log_handler = getattr(self.session, "_log_handler", None)
        if log_handler != None:
            log_handler.SetRenderer(None)
        self.end()

    def start(self, plugin_name=None, kwargs=None):
        """The method is called when new output is required.

        Metadata about the running plugin is provided so the renderer may log it
        if desired.

        Args:
           plugin_name: The name of the plugin which is running.
           kwargs: The args for this plugin.
        """
        _ = plugin_name
        _ = kwargs
        self._started = True

        # This handles the progress messages from rekall for the duration of
        # the rendering.
        if self.session:
            self.session.progress.Register(id(self), self.RenderProgress)

        return self

    def end(self):
        """Tells the renderer that we finished using it for a while."""
        self._started = False

        # Remove the progress handler from the session.
        if self.session:
            self.session.progress.UnRegister(id(self))

        self.flush()

    # DEPRECATED
    def write(self, data):
        """Renderer should write some data."""
        pass

    def section(self, name=None, width=50):
        """Start a new section.

        Sections are used to separate distinct entries (e.g. reports of
        different files).
        """
        _ = name
        _ = width

    def format(self, formatstring, *data):
        """Write formatted data.

        For renderers that need access to the raw data (e.g. to check for
        NoneObjects), it is preferred to call this method directly rather than
        to format the string in the plugin itself.

        By default we just call the format string directly.
        """
        _ = formatstring
        _ = data
        if not self._started:
            raise RuntimeError("Writing to a renderer that is not started.")

    def flush(self):
        """Renderer should flush data."""
        if self.table:
            self.table.flush()
            self.table = None

    def table_header(self, columns=None, **options):
        """Table header renders the title row of a table.

        This also stores the header types to ensure everything is formatted
        appropriately.  It must be a list of specs rather than a dict for
        ordering purposes.
        """
        if not self._started:
            raise RuntimeError("Renderer is used without a context manager.")

        # Ensure the previous table is flushed.
        if self.table:
            self.table.flush()

        self.table = self.table_class(session=self.session, renderer=self,
                                      columns=columns, **options)

    def table_row(self, *row, **kwargs):
        """Outputs a single row of a table."""
        self.table.render_row(row=row, **kwargs)

    def report_error(self, message):
        """Render the error in an appropriate way."""
        # By default just log the error. Visual renderers may choose to render
        # errors in a distinctive way.
        # TODO(jordi): Remove in 3 months when any usage should have been
        # noticed and fixed.
        logging.error(
            "**DEPRECATED** report_error is deprecated. Please use the session "
            "logging feature instead. Original message was: %s", message)
        self.session.logging.error(
            "**DEPRECATED** (via report_error): %s", message)

    def RenderProgress(self, *_, **kwargs):
        """Will be called to render a progress message to the user."""
        # Only write once per self.progress_interval.
        now = time.time()
        force = kwargs.get("force")

        # GC is expensive so we need to do it less frequently.
        if now > self.last_gc_time + 10:
            gc.collect()
            self.last_gc_time = now

        if force or now > self.last_spin_time + self.progress_interval:
            self.last_spin_time = now

            # Signal that progress must be written.
            return True

        return False

    def open(self, directory=None, filename=None, mode="rb"):
        """Opens a file for writing or reading."""
        _ = directory
        _ = filename
        _ = mode
        raise IOError("Renderer does not support writing to files.")

    def get_object_renderer(self, target=None, type=None, target_renderer=None,
                            **options):
        if target_renderer is None:
            target_renderer = self

        if isinstance(type, basestring):
            obj_renderer = ObjectRenderer.ByName(type, target_renderer)
            if not obj_renderer:
                # We don't want to blow up because we might still find the
                # renderer once we actually get the MRO.
                return None

        elif type is not None:
            obj_renderer = ObjectRenderer.ForType(type, target_renderer)
        else:
            obj_renderer = ObjectRenderer.ForTarget(target, target_renderer)

        if not obj_renderer:
            # This should never happen if the renderer installs a handler for
            # type object.
            # pylint: disable=protected-access
            raise RuntimeError("Unable to render object %r for renderer %s" %
                               (repr(target), target_renderer) +
                               str(ObjectRenderer._RENDERER_CACHE))

        return obj_renderer(renderer=self, session=self.session, **options)

    def Log(self, record):
        """Logs a log message. Implement if you want to handle logging."""


def CopyObjectRenderers(args, renderer=None):
    """Automatically copy the object renderers for a renderer.

    This is a convenience method which automatically generates the handlers for
    the given renderer by copying them from the object renderers given in args.

    Args:
      args: classes to copy.

      renderer: A string describing the renderer to apply the object renderers
      to.

    Return:
      Nothing - new renderers are automatically registered.

    """
    for arg in args:
        # Make a new unique name.
        new_class_name = renderer + arg.__name__
        type(new_class_name, (arg,), dict(renderers=[renderer]))
