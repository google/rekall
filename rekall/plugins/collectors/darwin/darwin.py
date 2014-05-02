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
Common Darwin collectors.
"""
__author__ = "Adam Sindelar <adamsh@google.com>"

from rekall import components
from rekall import identity


def ParseProcess(proc):
    process = components.Process(
        pid=proc.pid,
        command=proc.p_comm,
        parent_identity=identity.ProcessIdentity(pid=proc.p_ppid),
        user_identity=identity.UserIdentity(uid=proc.p_uid),
        arguments=None,
    )

    named = components.Named(
        name="PID %d" % proc.pid,
        kind="Process",
    )

    memory_obj = components.MemoryObject(
        base_object=proc,
        type="proc",
    )

    user = components.User(
        uid=proc.p_uid,
        username=None,
        home_dir=None,
        real_name=None,
    )

    user_named = components.Named(
        name=None,
        kind="User",
    )

    yield identity.ProcessIdentity(pid=proc.pid), [process, named, memory_obj]
    yield identity.UserIdentity(uid=proc.p_uid), [user, user_named]


def DarwinPgrpHashProcessCollector(profile):
    """Generates Process entities using hash of process groups.

    Adapted from legacy pslist plugin's list_using_pgrp_hash.

    XNU Reference:
      xnu-1699.26.8/bsd/sys/proc_internal.h
    """
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

    pgr_hash_table = profile.get_constant_object(
        "_pgrphashtbl",
        target="Pointer",
        target_args=dict(
            target="Array",
            target_args=dict(
                target="pgrphashhead",
                count=profile.get_constant_object(
                    "_pgrphash", "unsigned long") + 1
            )
        )
    )

    for slot in pgr_hash_table.deref():
        for pgrp in slot.lh_first.walk_list("pg_hash.le_next"):
            for proc in pgrp.pg_members.lh_first.walk_list(
                "p_pglist.le_next"):
                for result in ParseProcess(proc):
                    yield result


def DarwinTaskProcessCollector(profile):
    """List processes using the processor tasks queue.

    Adapted from legacy pslist plugin's list_using_task.

    XNU reference:
      /osfmk/kern/processor.c (processor_set_things)
    """
    tasks = profile.get_constant_object(
        "_tasks",
        target="queue_entry",
        vm=profile.session.kernel_address_space
    )

    for task in tasks.list_of_type("task", "tasks"):
        proc = task.bsd_info.deref()
        if proc:
            for result in ParseProcess(proc):
                yield result


def DarwinAllprocProcessCollector(profile):
    """List all processes by following the _allproc list head.

    Adapted from legacy pslist plugin's list_using_allproc.

    References TBD.
    """
    allproc = profile.get_constant_object(
        "_allproc", target="proclist")
    for proc in allproc.lh_first.p_list:
        for result in ParseProcess(proc):
            yield result


def DarwinPidHashProcessCollector(profile):
    """List processes using pid hash tables.

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

    pid_hash_table = profile.get_constant_object(
        "_pidhashtbl",
        target="Pointer",
        target_args=dict(
            target="Array",
            target_args=dict(
                target="pidhashhead",
                count=profile.get_constant_object(
                    "_pidhash", "unsigned long") + 1
            )
        )
    )

    for plist in pid_hash_table.deref():
        for proc in plist.lh_first.walk_list("p_hash.le_next"):
            if proc:
                for result in ParseProcess(proc):
                    yield result

