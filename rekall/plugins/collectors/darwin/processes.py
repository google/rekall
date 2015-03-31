# Rekall Memory Forensics
#
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

"""
Darwin Process collectors.
"""
__author__ = "Adam Sindelar <adamsh@google.com>"

from rekall import utils

from rekall.entities import definitions

from rekall.plugins.collectors.darwin import common
from rekall.plugins.collectors.darwin import zones


class DarwinProcParentInferor(common.DarwinEntityCollector):
    """Builds the parent-child relationships for processes."""

    outputs = ["Process"]

    collect_args = dict(processes="has component Process")
    complete_input = True

    def collect(self, hint, processes):
        by_pid = {}
        to_decorate = []
        for process in processes:
            pid = process["Process/pid"]
            collision = by_pid.get(pid)
            if collision:
                # Collision on PIDs. Keep the later process, since the earlier
                # one is definitely dead.
                start_time = process["Timestamps/created_at"]
                if start_time < collision["Timestamps/created_at"]:
                    # Keep the collision.
                    continue

            by_pid[pid] = process
            to_decorate.append(process)

        for process in to_decorate:
            ppid = process["Struct/base"].p_ppid
            parent = by_pid.get(ppid, None)
            if parent is None:
                continue

            parent_start = parent["Timestamps/created_at"]
            process_start = process["Timestamps/created_at"]

            if parent_start > process_start:
                continue

            yield [process.identity,
                   definitions.Process(
                       parent=parent.identity)]


class DarwinProcParser(common.DarwinEntityCollector):
    """Takes the proc structs found by various collectors and parses them."""

    outputs = ["Process",
               "User",
               "Timestamps",
               "Named/kind=process",
               "Struct/type=session"]

    collect_args = dict(procs="Struct/type is 'proc'")

    def collect(self, hint, procs):
        manager = self.manager
        for entity in procs:
            proc = entity["Struct/base"]
            user_identity = manager.identify({
                "User/uid": proc.p_uid})
            process_identity = manager.identify({
                ("Process/pid", "Timestamps/created_at"): (
                    proc.pid,
                    proc.p_start.as_datetime())})

            # kern_proc.c:2706
            session = proc.p_pgrp.pg_session
            if session:
                session_identity = manager.identify({
                    "Struct/base": session})

                yield definitions.Struct(base=session,
                                         type="session")
            else:
                session_identity = None

            cr3 = proc.task.map.pmap.pm_cr3
            if cr3:
                cr3_ptr = proc.obj_profile.Pointer(
                    vm=self.session.physical_address_space,
                    target="void",
                    value=proc.task.map.pmap.pm_cr3)
            else:
                cr3_ptr = None

            yield [
                # Reuse the base object identity but also use the PID.
                process_identity | entity.identity,
                definitions.Timestamps(
                    created_at=proc.p_start.as_datetime()),
                definitions.Process(
                    pid=proc.pid,
                    command=utils.SmartUnicode(proc.p_comm),
                    user=user_identity,
                    cr3=cr3_ptr,
                    is_64bit=proc.task.map.pmap.pm_task_map == "TASK_MAP_64BIT",
                    session=session_identity),
                definitions.Named(
                    name="%s (pid=%d)" % (proc.p_comm, proc.pid),
                    kind="Process")]

            # We don't know much about the user at this stage, but this
            # is still kind of useful in getting at least a list of UIDs.
            # Once we have more robustness in listing users this can go away.
            yield [user_identity,
                   definitions.User(uid=proc.p_uid)]


class DarwinPgrpHashProcessCollector(common.DarwinEntityCollector):
    """Lists processes using hashtable of process groups.

    Adapted from legacy pslist plugin's list_using_pgrp_hash.

    XNU Reference:
      xnu-1699.26.8/bsd/sys/proc_internal.h
    """

    _name = "pgrphash"
    outputs = ["Struct/type=proc"]

    def collect(self, hint):
        # Note that _pgrphash is initialized through:
        #
        # xnu-1699.26.8/bsd/kern/kern_proc.c:195
        # hashinit(int elements, int type, u_long *hashmask)
        #
        # /xnu-1699.26.8/bsd/kern/kern_subr.c: 327
        # hashinit(int elements, int type, u_long *hashmask) {
        #    ...
        # *hashmask = hashsize - 1;
        #
        # Hence the value in _pgrphash is one less than the size of the hash
        # table.
        pgr_hash_table = self.profile.get_constant_object(
            "_pgrphashtbl",
            target="Pointer",
            target_args=dict(
                target="Array",
                target_args=dict(
                    target="pgrphashhead",
                    count=self.profile.get_constant_object(
                        "_pgrphash", "unsigned long") + 1)))

        for slot in pgr_hash_table.deref():
            for pgrp in slot.lh_first.walk_list("pg_hash.le_next"):
                for proc in pgrp.pg_members.lh_first.walk_list(
                        "p_pglist.le_next"):
                    yield definitions.Struct(
                        base=proc,
                        type="proc")


class DarwinTaskProcessCollector(common.DarwinEntityCollector):
    """Lists processes using the processor tasks queue.

    Adapted from legacy pslist plugin's list_using_task.

    XNU reference:
      /osfmk/kern/processor.c (processor_set_things)
    """

    _name = "tasks"
    outputs = ["Struct/type=proc"]

    def collect(self, hint):
        tasks = self.profile.get_constant_object(
            "_tasks",
            target="queue_entry",
            vm=self.session.kernel_address_space)

        for task in tasks.list_of_type("task", "tasks"):
            proc = task.bsd_info.deref()
            if not proc:
                continue

            yield definitions.Struct(
                base=proc,
                type="proc")


class DarwinAllprocProcessCollector(common.DarwinEntityCollector):
    """Lists all processes by following the _allproc list head.

    Adapted from legacy pslist plugin's list_using_allproc.

    References TBD.
    """

    _name = "allproc"
    outputs = ["Struct/type=proc"]

    def collect(self, hint):
        allproc = self.profile.get_constant_object(
            "_allproc", target="proclist")
        for proc in allproc.lh_first.p_list:
            yield definitions.Struct(
                base=proc,
                type="proc")


class DarwinPidHashProcessCollector(common.DarwinEntityCollector):
    """Lists processes using pid hash tables.

    Adapted from legacy pslist plugin's list_using_pid_hash.

    XNU reference:
      xnu-1699.26.8/bsd/kern/kern_proc.c:834:
    """
    # Note that _pidhash is initialized through:
    #
    # xnu-1699.26.8/bsd/kern/kern_proc.c:194
    # pidhashtbl = hashinit(maxproc / 4, M_PROC, &pidhash);
    #
    # /xnu-1699.26.8/bsd/kern/kern_subr.c: 327
    # hashinit(int elements, int type, u_long *hashmask) {
    #    ...
    # *hashmask = hashsize - 1;
    #
    # Hence the value in pidhash is one less than the size of the hash
    # table.

    _name = "pidhash"
    outputs = ["Struct/type=proc"]

    def collect(self, hint):
        pid_hash_table = self.profile.get_constant_object(
            "_pidhashtbl",
            target="Pointer",
            target_args=dict(
                target="Array",
                target_args=dict(
                    target="pidhashhead",
                    count=self.profile.get_constant_object(
                        "_pidhash", "unsigned long") + 1)))

        for plist in pid_hash_table.deref():
            for proc in plist.lh_first.walk_list("p_hash.le_next"):
                if not proc:
                    continue

                yield definitions.Struct(
                    base=proc,
                    type="proc")


class DarwinDeadProcessCollector(zones.DarwinZoneElementCollector):
    """Lists dead processes using the proc allocation zone."""

    outputs = ["Struct/type=proc"]
    zone_name = "proc"
    type_name = "proc"

    _name = "deadprocs"

    def validate_element(self, proc):
        return (proc.p_argc > 0
                and len(proc.p_comm) > 0
                and proc.p_start.v() > 0
                and 99999 > proc.pid > 0)
