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

"""This module implements a text based render.

A renderer is used by plugins to produce formatted output.
"""

from __future__ import absolute_import

import json

from rekall import obj
from rekall import constants

from rekall.ui import renderer


class JsonFormatter(renderer.Formatter):
    """A formatter for json object."""

    def format_dict(self, value):
        result = []
        for k, v in value.items():
            result.append((k, self.format_field(v, "s")))

        return dict(result)

    def format_field(self, value, format_spec):
        """The json formatter aims to capture as many properties of the value as
        possible.
        """
        # We try to capture as much information about this object. Hopefully
        # this should be enough to reconstruct this object later.
        if isinstance(value, obj.BaseObject):
            result = dict(rekall_type=value.obj_type,
                          rekall_name=value.obj_name,
                          rekall_offset=value.obj_offset,
                          rekall_vm=str(value.obj_vm))

            for method in ["__unicode__", "__int__", "__str__"]:
                try:
                    result['value'] = self.format_field(
                        getattr(value, method)(), "s")['value']
                    break
                except (AttributeError, ValueError):
                    pass


            return result

        # If it is a simple type, just pass it as is.
        if isinstance(value, (int, long, basestring)):
            return dict(value=value)

        # If it is a NoneObject dump out the error
        if isinstance(value, obj.NoneObject):
            return dict(rekall_type=value.__class__.__name__,
                        rekall_reason=value.reason,
                        value=None)

        # Fall back to just formatting it.
        return super(JsonFormatter, self).format_field(value, format_spec)

class JsonColumn(renderer.BaseColumn):
    """A column in a JSON table."""

    def __init__(self, *args, **kwargs):
        super(JsonColumn, self).__init__(*args, **kwargs)

        self.formatter = JsonFormatter()

    def render_header(self):
        return self.cname

    def render_cell(self, target):
        return self.formatter.format_field(target, "s")


class JsonTable(renderer.BaseTable):
    """Implementation that outputs JSON."""

    column_class = JsonColumn

    def __init__(self, **kwargs):
        super(JsonTable, self).__init__(**kwargs)

    def render_header(self):
        self.renderer.table_data["headers"] = [
            c.render_header()
            for c in self.columns
        ]

    def get_header(self):
        return [c.render_header() for c in self.columns]

    def render_row(self, row=None, **_):
        data = {}
        for c, x in zip(self.columns, row):
            data[c.cname] = c.render_cell(x)
        self.renderer.table_data.append(data)


class JsonRenderer(renderer.BaseRenderer):
    """Render the output as a json object."""

    table_cls = JsonTable

    def start(self, plugin_name=None, kwargs=None):
        self.formatter = JsonFormatter()

        # We store the data here.
        self.data = dict(plugin_name=plugin_name,
                         tool_name="rekall-ng",
                         tool_version=constants.VERSION,
                         kwargs=self.formatter.format_dict(kwargs or {}),
                         data=[])

        super(JsonRenderer, self).start(plugin_name=plugin_name,
                                        kwargs=kwargs)
        self.headers = []

    def end(self):
        # Just dump out the json object.
        self.fd.write(json.dumps(self.data, indent=4))

    def format(self, formatstring, *args):
        statement = [formatstring]
        for arg in args:
            # Just store the statement in the output.
            statement.append(self.formatter.format_field(arg, "s"))

        self.data['data'].append(statement)

    def table_header(self, columns=None, **_):
        self.table = JsonTable(columns=columns, renderer=self)

        # This is the current table - the JsonTable object will write on it.
        self.table_data = []

        # Append it to the data.
        self.data['data'] = self.table_data

        # Write the headers.
        self.headers = self.table.get_header()

    def write(self, data):
        self.data['data'].append(data)

    def flush(self):
        self.data = []
        self.fd.flush()

