# Rekall Memory Forensics
# Copyright (C) 2012 Michael Cohen
# Copyright 2014 Google Inc. All Rights Reserved.
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

"""This module implements a pass-through renderer.

The renderer in this module just passes table rows along as it received them.
"""

from rekall.ui import renderer as renderer_module


class IdentityRenderer(renderer_module.BaseRenderer):
    columns = None
    plugin_name = None
    rows = None

    def __init__(self, *_, **kwargs):
        super(IdentityRenderer, self).__init__(session=kwargs.get("session"))
        self.rows = []
        self.delegated_renderer = self.session.GetRenderer()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def format(self, *args):
        self.delegated_renderer.format(*args)

    def flush(self):
        self.delegated_renderer.flush()

    def start(self, plugin_name=None, **_):
        super(IdentityRenderer, self).start(plugin_name=plugin_name, **_)
        self.plugin_name = plugin_name
        return self

    def table_header(self, columns=None, **_):
        self.columns = []
        for column in columns:
            if isinstance(column, dict):
                self.columns.append(column)
            elif isinstance(column, tuple):
                self.columns.append(dict(name=column[0],
                                         formatstring=column[2]))
            else:
                raise TypeError("Column spec must be dict or tuple. Got %r."
                                % column)

    def _get_column_name(self, idx):
        column = self.columns[idx]
        if isinstance(column, tuple):
            return column[1]

        return column["name"]

    def table_row(self, *values, **_):
        row = dict()
        for idx, value in enumerate(values):
            name = self._get_column_name(idx)
            row[name] = value

        self.rows.append(row)

    def open(self, **kwargs):
        return self.delegated_renderer.open(**kwargs)
