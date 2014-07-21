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
responsible for rendering these special objects using pluaggable
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
from rekall import registry


config.DeclareOption(
    "-v", "--verbose", default=False, action="store_true",
    help="Set logging to debug level.", group="Output control")

config.DeclareOption(
    "-q", "--quiet", default=False, action="store_true",
    help="Turn off logging to stderr.", group="Output control")

config.DeclareOption(
    "--debug", default=False, action="store_true",
    help="If set we break into the debugger on error conditions.")


class ObjectRenderer(object):
    """Baseclass for all TestRenderer object renderers."""

    # Fall back renderer for all objects.
    renders_type = "object"

    # These are the renderers supported by this object renderer.
    renderers = []

    __metaclass__ = registry.MetaclassRegistry

    # A cache of Renderer, MRO mappings.
    _RENDERER_CACHE = None

    def __init__(self, renderer=None, session=None, **options):
        self.renderer = renderer
        self.session = session
        self.options = options

    @staticmethod
    def get_mro(item):
        """Return the MRO of an item."""
        # Allow the item to override its MRO. This is useful for objects which
        # want to be a standin replacement for another object.
        get_mro = getattr(item, "get_mro", None)
        if get_mro:
            return item.get_mro()

        if not inspect.isclass(item):
            item = item.__class__

        # Remove duplicated class names from the MRO (The current implementation
        # uses the flat class name to select the ObjectRenderer so we can get
        # duplicates but they dont matter).
        return list(collections.OrderedDict.fromkeys(
            [x.__name__ for x in item.__mro__]))

    @classmethod
    def ByName(cls, name, renderer):
        """A constructor for an ObjectRenderer by name."""
        cls._BuildRendererCache()

        if isinstance(renderer, basestring):
            renderer = BaseRenderer.classes[renderer]

        # Find the object renderer which works for this name.
        for renderer_cls in ObjectRenderer.get_mro(renderer):
            result = cls._RENDERER_CACHE.get((name, renderer_cls))
            if result:
                return result

    @classmethod
    def _BuildRendererCache(cls):
        # Build the cache if needed.
        if cls._RENDERER_CACHE is None:
            cls._RENDERER_CACHE = {}
            for object_renderer_cls in cls.classes.values():
                for impl_renderer in object_renderer_cls.renderers:
                    key = (object_renderer_cls.renders_type, impl_renderer)
                    cls._RENDERER_CACHE[key] = object_renderer_cls

    @classmethod
    def ForTarget(cls, target, renderer):
        """Get the best ObjectRenderer for this target.

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
        cls._BuildRendererCache()

        if isinstance(renderer, basestring):
            renderer = BaseRenderer.classes[renderer]

        # Search for a handler which supports both the renderer and the object
        # type.
        for mro_cls in cls.get_mro(target):
            for renderer_cls in cls.get_mro(renderer):
                handler = cls._RENDERER_CACHE.get((mro_cls, renderer_cls))
                if handler:
                    return handler

    @classmethod
    def cache_key(cls, item):
        """Return a suitable cache key."""
        return repr(item)

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

    sort_key_func = None
    deferred_rows = None

    last_spin_time = 0
    last_gc_time = 0
    progress_interval = 0.2

    # This is used to ensure that renderers are always called as context
    # managers. This guarantees we call start() and end() automatically.
    _started = False

    def __init__(self, session=None):
        self.session = session

    def __enter__(self):
        self._started = True
        return self

    def __exit__(self, exc_type, exc_value, trace):
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
        if self.deferred_rows is not None:
            # Table was sorted. Render deferred rows now.
            self.flush_table()

        # Remove the progress handler from the session.
        if self.session:
            self.session.progress.UnRegister(id(self))

        self.flush()

    # DEPRECATED
    def write(self, data):
        """Renderer should write some data."""
        pass

    def section(self, name=None, width=50, keep_sort=False):
        """Start a new section.

        Sections are used to separate distinct entries (e.g. reports of
        different files).
        """
        if self.deferred_rows is not None:
            # Table is sorted. Print deferred rows from last section now.
            self.flush_table(keep_sort=keep_sort)

        if name is None:
            self.format("*" * width + "\n")
        else:
            pad_len = width - len(name) - 2  # 1 space on each side.
            padding = "*" * (pad_len / 2)  # Name is centered.

            self.format("{0}", "\n{0} {1} {2}\n".format(padding, name,
                        padding))

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
        pass

    def table_header(self, columns=None, name=None, sort=None, **options):
        """Table header renders the title row of a table.

        This also stores the header types to ensure everything is formatted
        appropriately.  It must be a list of tuples rather than a dict for
        ordering purposes.

        Args:
          columns: A list of (name, cname, formatstring) tuples describing
            the table headers.

          name: The name of this table.

          sort: Optional - tuple of cnames of columns to sort by. If sorting
          sorting is on, rendering of table rows will be deferred either
          until next call to table_header (or section) or until the plugin
          render function ends.

          **options: Arbitrary options to pass to the table
            implementations. These depend on the specific
            implementation. Options which do not make sense for the
            implementation will be ignored.
        """
        _ = name
        self.columns = columns
        if not self._started:
            raise RuntimeError("Renderer is used without a context manager.")

        if self.deferred_rows is not None:
            # Previous table we rendered was sorted. Do deferred rendering now.
            self.flush_table()

        self.table = self.table_cls(
            renderer=self, session=self.session, columns=columns, **options
        )

        self.table.render_header()

        if sort:
            self.sort_key_func = self._build_sort_key_function(
                sort_cnames=sort,
                columns=columns,
            )
            self.deferred_rows = []

    @staticmethod
    def _build_sort_key_function(sort_cnames, columns):
        """Builds a function that takes a row and returns keys to sort on."""
        cnames_to_indices = {}
        for idx, (_, cname, _) in enumerate(columns):
            cnames_to_indices[cname] = idx

        sort_indices = [cnames_to_indices[x] for x in sort_cnames]

        # Row is a tuple of (values, kwargs) - hence row[0][index].
        return lambda row: [row[0][index] for index in sort_indices]

    def table_row(self, *args, **kwargs):
        """Outputs a single row of a table."""

    def flush_table(self, keep_sort=False):
        """If sorting is on, this will trigger deferred rendering."""
        self.deferred_rows.sort(key=self.sort_key_func)

        for row, kwargs in self.deferred_rows:
            self.table.render_row(
                row=row,
                **kwargs
            )

        if keep_sort:
            self.deferred_rows = []
        else:
            self.deferred_rows = None
            self.sort_key_func = None

    def report_error(self, message):
        """Render the error in an appropriate way."""
        # By default just log the error. Visual renderers may choose to render
        # errors in a distinctive way.
        logging.error(message)

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

    def get_object_renderer(self, target=None, type=None, **options):
        if type is not None:
            result = ObjectRenderer.ByName(type, self)(
                self, session=self.session, **options)

            if result is None:
                raise TypeError(
                    "No renderer found for %s which was explicitly forced." %
                    type)

            return result

        handler = ObjectRenderer.ForTarget(target, self)
        if handler:
            return handler(renderer=self, session=self.session, **options)

        # This should never happen if the renderer installs a handler for
        # object().
        raise RuntimeError("Unable to render object")
