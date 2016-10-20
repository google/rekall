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

"""Location handlers.

A location is an object which handles file transfer to a specific place.
"""
from rekall_agent import common
from rekall_agent import serializer


class Status(object):
    """Represents the status of a network operation."""

    def __init__(self, code=200, reason=""):
        self.code = code
        self.reason = reason


class Location(common.AgentConfigMixin, serializer.SerializedObject):
    """A type specifying a location to upload/download files."""

    # This one object can represent a number of location types.
    schema = []

    def to_path(self):
        return ""

    def read_file(self):
        """Gets the contents of location as a string."""
        raise NotImplementedError()

    def write_file(self, data):
        """Writes data to the location."""
        raise NotImplementedError()

    def upload_local_file(self, local_filename, completion_routine=None,
                          sync=False):
        """Upload the local file to the location.

        This function will retry and might take some time to complete. If a
        completion_routine is provided it will be called with a Status() object
        representing the outcome of the operation.
        """
        raise NotImplementedError()

    def get_local_filename(self):
        """Returns a local filename which can be used to access this object.

        If the object is remote, a local copy is made on the filesystem into a
        temporary file, and this filename is returned.
        """
        raise NotImplementedError()


class LocationStat(serializer.SerializedObject):
    """Information about a file."""
    schema = [
        dict(name="location", type=Location,
             doc="The location whos stat this is."),

        dict(name="created", type="epoch",
             doc="When it was created."),

        dict(name="updated", type="epoch",
             doc="When it was created."),

        dict(name="size", type="int",
             doc="Size of this object"),

        dict(name="generation",
             doc="A unique timestamp for this version of the object.")
    ]
