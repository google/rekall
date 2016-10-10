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
import time
import psutil

from rekall_agent import serializer


class Resources(serializer.SerializedObject):
    """Measure resource usage."""

    schema = [
        dict(name="user_time", type="float"),
        dict(name="system_time", type="float"),
        dict(name="wall_time", type="float"),
    ]

    _start_user_time = _start_system_time = _start_wall_time = 0
    _counting = False

    def start(self):
        """Reset internal resource counters and start measuring."""
        cpu_times = psutil.cpu_times()

        self._start_user_time = cpu_times.user
        self._start_system_time = cpu_times.system
        self._start_wall_time = time.time()
        self._counting = True
        self._signal_modified()

    def stop(self):
        """Stop measuring."""
        self._counting = False

    def update(self):
        cpu_times = psutil.cpu_times()
        if self._counting:
            self.user_time = cpu_times.user - self._start_user_time
            self.system_time = cpu_times.system - self._start_system_time
            self.wall_time = time.time() - self._start_wall_time

    def to_primitive(self):
        """Freeze the current resources upon serialization."""
        self.update()
        return super(Resources, self).to_primitive(self)

    @property
    def total_time(self):
        self.update()
        return self.user_time + self.system_time


class Quota(Resources):
    schema = [
        dict(name="used", type=Resources,
             doc="The resources actually used."),
    ]

    def start(self):
        self.used.start()

    def check(self):
        """Ensure our resource use does not exceed the quota."""
        return self.used.total_time <= self.total_time
