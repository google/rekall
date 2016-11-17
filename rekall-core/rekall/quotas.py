# Rekall
# Copyright (C) 2016 Michael Cohen <scudette@gmail.com>
# Copyright 2016 Google Inc. All Rights Reserved.
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

"""This file implements CPU quota limiting on the Rekall session.

The code works by wrapping a session object with progress handlers
which check for the CPU quota.

Note that when Rekall is used as a library, the caller must
deliberately wrap its own session with this module.
"""
import time

import psutil

from rekall import config
from rekall import plugin


config.DeclareOption(
    "--cpu_quota", type="IntParser", group="Quotas",
    help="Number of allocated CPU seconds Rekall is allowed to consume. "
    "If not set, unlimited CPU time can be used.")

config.DeclareOption(
    "--load_quota", type="IntParser", group="Quotas",
    help="The target maximal process load level (in percent).")


def wrap_session(session, cpu_quota=None, load_quota=None):
    """Wraps the session limiting cpu quota."""
    if load_quota is None:
        load_quota = session.GetParameter("load_quota")

    if cpu_quota is None:
        cpu_quota = session.GetParameter("cpu_quota")

    if cpu_quota == None and load_quota == None:
        return session

    # Store the process's current CPU utilization.
    proc = psutil.Process()
    cpu_times = proc.cpu_times()
    start_time = cpu_times.user + cpu_times.system
    state = dict(last=time.time(),
                 start_time=start_time,
                 proc=proc)

    def quota_callback(*_, **__):
        check_quota(state, cpu_quota, load_quota)

    # Register our progress dispatcher.
    session.progress.Register("quota", quota_callback)
    return session


def check_quota(state, cpu_quota, load_quota):
    """A progress callback which checks quota is not exceeded."""
    now = time.time()

    # In order to not overwhelm psutil we throttle calls to once every
    # few ms.
    if now + 0.5 > state["last"]:
        state["last"] = now
        start_time = state["start_time"]
        proc = state["proc"]
        cpu_times = proc.cpu_times()
        current = cpu_times.user + cpu_times.system
        if cpu_quota and current > start_time + cpu_quota:
            # CPU quota exceeded.
            raise plugin.PluginError("CPU Quota exceeded (%s Seconds)." %
                                     (current - start_time))

        if load_quota:
            while 1:
                current_cpu_percent = proc.cpu_percent() * 100

                # If our current CPU utilization exceeds the specified
                # limits we sleep a bit.
                if current_cpu_percent < load_quota:
                    break

                time.sleep(0.1)
