"""A client action which runs arbitrary plugins.

This action runs the plugin with the provided arguments and outputs the result
into a collection.

Rekall uses renderers to convert the output to a desired output. There are two
useful formats which Rekall produces. The TextRenderer produces textual output
(which is the default output for the command line). The DataExportRenderer
produces more structured data which can be used for further processing.

Generally, the DataExportRenderer produces output which is useful for UIs as a
context menu item. It is not supposed to be useful in all processing steps. If
you want to build a stable pipeline for processing Rekall's output, you should
use the CollectAction() to specify exactly the required data.


In this Action we include both the text and data export in each column output.
"""
import logging
import weakref

from rekall import plugin
from rekall import session
from rekall.ui import renderer
from rekall.plugins.renderers import data_export
from rekall.plugins.response import common
from rekall.ui import text
from rekall_lib.types import actions



class LogCapturer(logging.Handler):
    def __init__(self, owning_renderer, *args, **kwargs):
        self.renderer = owning_renderer
        super(LogCapturer, self).__init__(*args, **kwargs)

    def emit(self, record):
        self.renderer.emit_record(record)


class PluginRenderer(renderer.BaseRenderer):
    """A custom renderer to capture output."""

    def __init__(self, collection, flow_obj, **kwargs):
        super(PluginRenderer, self).__init__(**kwargs)
        self.collection = collection
        self.current_section = "data"
        self.section_number = 0
        self._text_renderer = text.TextRenderer(session=self.session)
        self._data_renderer = data_export.DataExportRenderer(
            session=self.session)
        self._uploaded_files = {}
        self._flow_obj = flow_obj
        self.collection.tables.append(dict(name="logs", columns=[
            dict(name="timestamp", type="epoch"),
            dict(name="level", type="int"),
            dict(name="source"),
            dict(name="message"),
        ]))

        handler = LogCapturer(self)
        logging.getLogger().addHandler(
            weakref.proxy(
                handler,
                lambda _, h=handler: logging.getLogger().removeHandler(h)))

    def emit_record(self, record):
        self.collection.insert(
            table="logs",
            message=record.getMessage(),
            timestamp=record.created,
            level=record.levelno,
            source="%s:%s" % (record.module, record.lineno))

    def section(self, name=None):
        if not name:
            self.section_number += 1
            self.current_section = "data_%s" % self.section_number

    def table_header(self, columns=None, **options):
        self.columns = []
        for column in (columns or []):
            self.columns.append(dict(name=column['name'], type="any"))
        self.collection.tables.append(dict(name="data", columns=self.columns))

    def table_row(self, *row, **kwargs):
        # Only used when a plugin returns a row as a list.
        for i, row_item in enumerate(row):
            kwargs[self.columns[i]["name"]] = row_item

        self.collection.insert(table=self.current_section,
                               **self.convert_row(kwargs))

    def convert_row(self, row):
        """Render the row into the output collection."""
        result = {}
        for k, v in row.iteritems():
            # Render both text and data export for each object.
            text_rendering = unicode(self._text_renderer.get_object_renderer(
                target=v).render_row(v))
            data_export_rendering = self._data_renderer.get_object_renderer(
                target=v).EncodeToJsonSafe(v)

            self.handle_special_objects(v)
            result[k] = dict(
                text=text_rendering,
                data=data_export_rendering,
            )
        return result

    def handle_special_objects(self, obj):
        """Special actions triggered on some exported objects."""
        if (isinstance(obj, common.FileInformation) and
            self._flow_obj.HasMember("file_upload")):
            with obj.open() as fd:
                self._flow_obj.file_upload.upload_file_object(fd)
                self._flow_obj.status.total_uploaded_files += 1


class PluginActionImpl(actions.PluginAction):

    def run(self, flow_obj=None):
        # Make sure to notify the flow status about the collection we are about
        # to create.
        flow_obj.status.collection_ids.append(self.collection.id)

        # Find the plugin we need to call.
        plugin_cls = plugin.Command.ImplementationByClass(self.plugin)
        if plugin_cls == None:
            raise plugin.PluginError("Unknown plugin")

        plugin_obj = plugin_cls(session=self._session, **self.args)
        if plugin_obj == None:
            raise plugin.PluginError("Plugin not active")

        # Sometimes we dont know all the columns until we actually run the
        # plugin (For example the Search plugin creates columns dynamically). It
        # is always safer to run the plugin through the renderer.
        with self.collection.start():
            plugin_obj.render(PluginRenderer(session=self._session,
                                             collection=self.collection,
                                             flow_obj=flow_obj))
