#!/usr/bin/env python2

# Rekall Memory Forensics
# Copyright 2016 Google Inc. All Rights Reserved.
#
# Author: Michael Cohen scudette@google.com
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

__author__ = "Michael Cohen <scudette@google.com>"

"""This module implements collections.

A collection is a file which keeps some related structured data together
(i.e. data can be thought of as tabulated). Collection can be big or small and
contain one or more tables.

Currently most collections are SQLite files, but other collection types may
be possible.

"""
from rekall_lib import serializer
from rekall_lib.rekall_types import location


class ColumnSpec(serializer.SerializedObject):
    """Specification of a single column."""

    schema = [
        dict(name="name", type="unicode"),
        dict(name="type", type="choices",
             choices=["int", "unicode", "str", "float", "epoch", "any"],
             doc="The type of this column. This must be a primitive type. "
             "(any must be a json serializable object)."),
    ]


class Table(serializer.SerializedObject):
    schema = [
        dict(name="name", doc="Name of the table."),
        dict(name="columns", type=ColumnSpec, repeated=True, hidden=True),
        dict(name="indexes", repeated=True, hidden=True),
    ]


class CollectionSpec(serializer.SerializedObject):
    """A Collection specification.

    This is used as the base class for all collections.
    """
    # Define tables inline for extended collections.
    _tables = None

    schema = [
        # Allow the collection to specify its name.
        dict(name="id",
             doc="A Unique ID for this collection."),

        dict(name="type",
             doc="A canonical type name for this collection."),

        dict(name="tables", type=Table, repeated=True, hidden=True,
             doc="A list of tables in this collection."),

        dict(name="location", type=location.Location,
             doc="Location of this collection."),
    ]

    def insert(self, table=None, **kwargs):
        """Insert a row into the collection."""
        raise NotImplementedError()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.flush()

    def flush(self):
        pass


class JSONCollection(CollectionSpec):
    """A collection which writes its result as JSON."""
    schema = [
        dict(name="max_rows", type="int", default=1000000,
             doc="Maximum number of rows we accumulate before sending."),
        dict(name="part_number", type="int"),

        dict(name="table_data", type="dict",
             doc="The data we are carrying. Key is table name, "
             "value is a list of rows with order dictated by the "
             "Table's ColumnSpec."),
    ]
