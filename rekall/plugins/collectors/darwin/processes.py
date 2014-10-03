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

from rekall.entities import definitions

from rekall.plugins.collectors.darwin import common
from rekall.plugins.collectors.darwin import zones


class DarwinProcParser(common.DarwinEntityCollector):
    """Takes the proc structs found by various collectors and parses them."""

    collects = [
        "Process",
        "User",
        "Timestamps",
        "Named/kind=process"]

    def collect(self, hint=None):
        manager = self.entity_manager
        for entity in manager.find_by_attribute(
                "MemoryObject/type", "proc"):

            proc = entity["MemoryObject/base_object"]
            user_identity = manager.identify({
                "User/uid": proc.p_uid})
            process_identity = manager.identify({
                "Process/pid": proc.pid})

            # kern_proc.c:2706
            session = proc.p_pgrp.pg_session
            if session:
                session_identity = manager.identify({
                    "MemoryObject/base_object": session})
            else:
                session_identity = None

            yield [
                # Reuse the base object identity but also use the PID.
                process_identity | entity.identity,
                definitions.Timestamps(
                    created_at=proc.p_start),
                definitions.Process(
                    pid=proc.pid,
                    command=str(proc.p_comm),
                    parent=manager.identify({"Process/pid": proc.p_ppid}),
                    user=user_identity,
                    session=session_identity),
                definitions.Named(
                    name="%s (pid=%d)" % (proc.p_comm, proc.pid),
                    kind="Process")]

            # We don't know much about the user at this stage, but this
            # is still kind of useful in getting at least a list of UIDs.
            # Once we have more robustness in listing users this can go away.
            yield [
                user_identity,
                definitions.User(uid=proc.p_uid)]


class DarwinPgrpHashProcessCollector(common.DarwinEntityCollector):
    """Lists processes using hashtable of process groups.

    Adapted from legacy pslist plugin's list_using_pgrp_hash.

    XNU Reference:
      xnu-1699.26.8/bsd/sys/proc_internal.h
    """

    _name = "pgrphash"
    collects = ["MemoryObject/type=proc"]

    def collect(self, hint=None):
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
                    yield definitions.MemoryObject(
                        base_object=proc,
                        type="proc")


class DarwinTaskProcessCollector(common.DarwinEntityCollector):
    """Lists processes using the processor tasks queue.

    Adapted from legacy pslist plugin's list_using_task.

    XNU reference:
      /osfmk/kern/processor.c (processor_set_things)
    """

    _name = "tasks"
    collects = ["MemoryObject/type=proc"]

    def collect(self, hint=None):
        tasks = self.profile.get_constant_object(
            "_tasks",
            target="queue_entry",
            vm=self.session.kernel_address_space)

        for task in tasks.list_of_type("task", "tasks"):
            proc = task.bsd_info.deref()
            if not proc:
                continue

            yield definitions.MemoryObject(
                base_object=proc,
                type="proc")


class DarwinAllprocProcessCollector(common.DarwinEntityCollector):
    """Lists all processes by following the _allproc list head.

    Adapted from legacy pslist plugin's list_using_allproc.

    References TBD.
    """

    _name = "allproc"
    collects = ["MemoryObject/type=proc"]

    def collect(self, hint=None):
        allproc = self.profile.get_constant_object(
            "_allproc", target="proclist")
        for proc in allproc.lh_first.p_list:
            yield definitions.MemoryObject(
                base_object=proc,
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
    collects = ["MemoryObject/type=proc"]

    def collect(self, hint=None):
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

                yield definitions.MemoryObject(
                    base_object=proc,
                    type="proc")


class DarwinDeadProcessCollector(zones.DarwinZoneElementCollector):
    """Lists dead processes using the proc allocation zone."""

    collects = ["MemoryObject/type=proc"]
    zone_name = "proc"
    type_name = "proc"

    _name = "deadprocs"

    def validate_element(self, proc):
        return proc.p_argc > 0
