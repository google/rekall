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

from rekall import plugin
from rekall.plugins.renderers import data_export
from rekall.plugins.response import common
from rekall.ui import text
from rekall_lib.types import actions


class PluginActionImpl(actions.PluginAction):

    def handle_special_objects(self, obj):
        """Special actions triggered on some exported objects."""
        if (isinstance(obj, common.FileInformation) and
            self._flow_obj.HasMember("file_upload")):
            with obj.open() as fd:
                self._flow_obj.file_upload.upload_file_object(fd)
                self._flow_obj.status.total_uploaded_files += 1

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

    def run(self, flow_obj=None):
        self._text_renderer = text.TextRenderer(session=self._session)
        self._data_renderer = data_export.DataExportRenderer(
            session=self._session)
        self._uploaded_files = {}
        self._flow_obj = flow_obj

        # Make sure to notify the flow status about the collection we are about
        # to create.
        flow_obj.status.collection_ids.append(self.collection.id)

        # Find the plugin we need to call.
        plugin_cls = plugin.Command.ImplementationByClass(self.plugin)
        if plugin_cls == None:
            raise plugin_cls.PluginError("Unknown plugin")

        plugin_obj = plugin_cls(session=self._session, **self.args)

        # We need to define the columns for the output collection.
        columns = []
        for column in plugin_obj.table_header:
            columns.append(dict(name=column['name'], type="any"))

        # Add a new table to the collection.
        self.collection.tables.append(dict(name="data", columns=columns))
        with self.collection.start():
            for row in plugin_obj:
                self.collection.insert(table="data", **self.convert_row(row))
