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
import tempfile
import time
import six

from rekall import plugin
from rekall.ui import renderer
from rekall.plugins.renderers import data_export
from rekall.plugins.response import common
from rekall.ui import text
from rekall_lib.rekall_types import actions
from rekall_lib import utils


class UploaderFileObject(object):
    """A File like object which uploads itself to the server."""
    def __init__(self, upload_location, name=None):
        self.upload_location = upload_location
        self.name = name
        self.fd = None

    def __enter__(self):
        self.fd = tempfile.NamedTemporaryFile()
        self.len = 0
        return self

    def __exit__(self, exc_type, exc_value, trace):
        self.flush()

    def seek(self, *args, **kwargs):
        self.fd.seek(*args, **kwargs)

    def write(self, data):
        self.fd.write(data)

    def tell(self):
        return self.fd.tell()

    def read(self, length):
        data = self.fd.read(length)
        return data

    def flush(self):
        """Upload the file."""
        try:
            self.fd.seek(0, 2)
            self.len = self.fd.tell() - 1
            self.fd.seek(0)
            self.upload_location.upload_file_object(self)
        finally:
            self.fd.close()


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

        self.handler = LogCapturer(self)

    def __enter__(self):
        self.session.logging.addHandler(self.handler)

    def __exit__(self, exc_type, exc_value, trace):
        self.session.logging.removeHandler(self.handler)

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
        for k, v in six.iteritems(row):
            # Render both text and data export for each object.
            text_rendering = utils.SmartUnicode(
                self._text_renderer.get_object_renderer(target=v).render_row(v))
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

    def open(self, filename, **kwargs):
        location = self._flow_obj.file_upload
        if location:
            self._flow_obj.status.total_uploaded_files += 1
            return UploaderFileObject(location, filename)
        else:
            raise IOError("No upload location")


class PluginActionImpl(actions.PluginAction):

    def run(self, flow_obj=None):
        plugin_renderer = PluginRenderer(session=self._session,
                                         collection=self.collection,
                                         flow_obj=flow_obj)
        with self.collection.start():
            with plugin_renderer:
                # Find the plugin we need to call.
                plugin_cls = plugin.Command.ImplementationByClass(self.plugin)
                if plugin_cls == None:
                    raise plugin.PluginError("Unknown plugin")

                # Sometimes we dont know all the columns until we actually run
                # the plugin (For example the Search plugin creates columns
                # dynamically). It is always safer to run the plugin through the
                # renderer.
                self._session.logging.info("Running plugin %s", plugin_cls)
                now = time.time()
                try:
                    self._session.RunPlugin(plugin_cls, format=plugin_renderer,
                                            **self.args)
                finally:
                    self._session.logging.info("Completed in %s seconds",
                                               time.time() - now)
