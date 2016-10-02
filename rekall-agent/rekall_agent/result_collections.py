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
import os
import tempfile
import sqlite3

import arrow

from rekall_agent import location
from rekall_agent import serializer


class ColumnSpec(serializer.SerializedObject):
    """Specification of a single column."""

    schema = [
        dict(name="name", type="unicode"),
        dict(name="type", type="choices",
             choices=["int", "unicode", "str", "float", "epoch",],
             doc="The type of this column. This must be a primitive type."),
    ]


class Table(serializer.SerializedObject):
    schema = [
        dict(name="name", doc="Name of the table."),
        dict(name="columns", type=ColumnSpec, repeated=True),
    ]


class CollectionSpec(serializer.SerializedObject):
    """A Collection specification.

    This is used as the base class for all collections.
    """
    # Define tables inline for extended collections.
    _tables = None

    schema = [
        dict(name="tables", type=Table, repeated=True,
             doc="A list of tables in this collection."),
    ]

    def query(self, query=None, table=None):
        """Query the collection.

        If table is not specified, queries the default table. Query can be
        interpreted depending on the collection's type.

        Yields dicts with keys being the columns and values for matching rows in
        the collection.
        """
        raise NotImplementedError()

    def insert(self, table=None, **kwargs):
        """Insert a row into the collection."""
        raise NotImplementedError()


SQLITE_TIMEOUT = 600.0
SQLITE_ISOLATION = "DEFERRED"
SQLITE_SUBJECT_SPEC = "TEXT"
SQLITE_DETECT_TYPES = 0
SQLITE_FACTORY = sqlite3.Connection
SQLITE_CACHED_STATEMENTS = 20
SQLITE_PAGE_SIZE = 1024


def _coerce_timestamp(value):
    if isinstance(value, arrow.Arrow):
        return value.float_timestamp

    return float(value)


class GenericSQLiteCollection(CollectionSpec):
    """A Collection based on SQLite files."""

    schema = [
        dict(name="location", type=location.Location,
             doc="Location of this collection."),
    ]

    _allowed_types = {
        "int": int,
        "unicode": unicode,  # Unicode data.
        "str": str, # Used for binary data.
        "float": float,

        # Dates as epoch timestamps are stored as floats.
        "epoch": _coerce_timestamp,

        "any": str  # Used for opaque types that can not be further processed.
    }

    def __init__(self, *args, **kwargs):
        super(GenericSQLiteCollection, self).__init__(*args, **kwargs)

        self._flush_cb = lambda: None

        # Allow the collection to be initialized from an class member.
        if not self.GetMember("tables") and self._tables:
            self.SetMember(
                "tables",
                [Table.from_primitive(x, session=self._session)
                 for x in self._tables])

    @classmethod
    def load_from_location(cls, collection_location=None, filename=None,
                           session=None):
        if filename is None:
            filename = collection_location.get_local_filename()

        conn = sqlite3.connect(
            filename, SQLITE_TIMEOUT, SQLITE_DETECT_TYPES,
            SQLITE_ISOLATION, False, SQLITE_FACTORY,
            SQLITE_CACHED_STATEMENTS)

        cursor = conn.cursor()
        try:
            for row in cursor.execute(
                    "select value from metadata where key='schema'"):
                result = cls.from_json(row[0], session=session)
        except sqlite3.Error:
            result = cls(session=session)

        result.location = collection_location
        result.load_from_local_file(filename)

        return result

    def create_temp_file(self):
        fd, local_filename = tempfile.mkstemp()
        os.close(fd)
        self.load_from_local_file(local_filename)

        def _flush_cb():
            """When finished with collection, upload it and then remove it."""
            with open(local_filename, "rb") as fd:
                self.location.upload_file_object(fd)

            os.unlink(local_filename)

        self._flush_cb = _flush_cb

        return self

    def load_from_local_file(self, filename):
        self._filename = filename
        self._conn = sqlite3.connect(
            self._filename, SQLITE_TIMEOUT, SQLITE_DETECT_TYPES,
            SQLITE_ISOLATION, False, SQLITE_FACTORY,
            SQLITE_CACHED_STATEMENTS)

        self._cursor = self._conn.cursor()
        self._cursor.row_factory = sqlite3.Row

        self._cursor.execute("PRAGMA count_changes = OFF")
        self._cursor.execute("PRAGMA cache_size = 10000")
        self._cursor.execute("PRAGMA journal_mode = WAL")

        self._queries = {}

        # Store metadata about the collection.
        self._cursor.execute(
            "CREATE TABLE IF NOT EXISTS metadata (key TEXT, value TEXT);")

        existing_schema = None
        for row in self._cursor.execute(
                "select value from metadata where key='schema'"):
            existing_schema = GenericSQLiteCollection.from_json(
                row["value"], session=self._session)

        if not existing_schema:
            existing_schema = self
            self._cursor.execute(
                "insert into metadata values(?, ?)", ("schema", self.to_json()))

        # Now parse the schema and create the relevant table.
        for table in self.tables:
            column_specs = []
            self._queries[table.name] = "insert into tbl_%s values (%s)" % (
                table.name, ",".join("?" * len(table.columns)))

            for column in table.columns:
                if column.type == "int" or column.type == "epoch":
                    column_specs.append(column.name + " BIG INTEGER")
                elif column.type in [None, "unicode"]:
                    column_specs.append(column.name + " TEXT")
                elif column.type == "str":
                    column_specs.append(column.name + " BLOB")
                elif column.type == "float":
                    column_specs.append(column.name + " REAL")

            self._cursor.execute("CREATE TABLE IF NOT EXISTS tbl_%s (%s);" % (
                table.name, ",".join(column_specs)))

    @classmethod
    def transaction(cls, collection_location, callback, *args, **kwargs):
        """Modify the collection safely.

        The callback will receive the collection object:

        callback(collection, *args)

        If this function completes, the modified collection is guaranteed to be
        consistent, even if another process or thread is trying to modify it at
        the same time.
        """
        def _read_modify_write(filename, session):
            collection = cls.load_from_location(filename=filename,
                                                session=session)
            # with forces cursors to be committed.
            with collection:
                callback(collection, *args)

        collection_location.read_modify_write_local_file(
            _read_modify_write, kwargs.pop("session"))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._conn.commit()
        self._conn.close()
        self._flush_cb()

    def _find_table(self, table=None):
        if isinstance(table, basestring):
            for i in self.tables:
                if i.name == table:
                    return i

        if table is None:
            if len(self.tables) > 1:
                RuntimeError("Collection contains multiple tables and no "
                             "table is specified.")
            return self.tables[0]

        raise RuntimeError("Unknown table %s" % table)

    def sanitize_row(self, row, table=None):
        """Convert the row into primitives.

        The collection can only store primitives and so we must convert the
        objects to these primitives.
        """
        table = self._find_table(table)
        sanitized_row = {}

        # Make sure we only collect the columns which are specified. NOTE:
        # The EFilter query must name the columns exactly the same as the
        # collection spec.
        for column in table.columns:
            value = row.get(column.name)
            if value is None:
                continue

            sanitized_row[column.name] = self._allowed_types[
                column.type or "unicode"](value)

        return sanitized_row

    def insert(self, table=None, row=None, **kwargs):
        table = self._find_table(table)
        sanitized_row = self.sanitize_row(row or kwargs)
        self._cursor.execute(
            self._queries[table.name],
            [sanitized_row.get(x.name) for x in table.columns])

    def replace(self, table=None, condition=None, **kwargs):
        table = self._find_table(table)
        kwargs = self.sanitize_row(kwargs)
        update_sql = ",".join("%s=?" % x for x in kwargs)
        update_sql = "update tbl_%s set %s where %s" % (
            table.name, update_sql, condition)

        self._cursor.execute(update_sql, kwargs.values())

    def __iter__(self):
        return self._query()

    def query(self, query=None, query_args=None, table=None, order_by=None,
              **kwargs):
        table = self._find_table(table)
        if query is None:
            query = "select * from tbl_%s" % table.name
            if not kwargs:
                kwargs[1] = 1

            query += " where " + " and ".join(["%s=?" % x for x in kwargs])
            if order_by:
                query += " order by " + order_by

            query_args = kwargs.values()

        for row in self._cursor.execute(query, query_args or ()):
            yield row

    def delete(self, table=None, **kwargs):
        table = self._find_table(table)
        if not kwargs:
            kwargs[1] = 1

        query = "delete from tbl_%s where " % table.name
        query += " and ".join(["%s=?" % x for x in kwargs])
        self._cursor.execute(query, kwargs.values())
