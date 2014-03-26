# Rekall Memory Forensics
#
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

"""
Darwin entity generators are all here.
"""
__author__ = "Adam Sindelar <adamsh@google.com>"

from rekall.plugins.darwin import entities


def DarwinNetworkInterfaceGenerator(profile):
    """Walks the global list of interfaces.

    The head of the list of network interfaces is a kernel global [1].
    The struct we use [2] is just the public part of the data [3]. Addresses
    are related to an interface in a N:1 relationship [4]. AF-specific data
    is a normal sockaddr struct.

    Yields:
      DarwinNetworkInterface entities.

    References:
      1:
      https://github.com/opensource-apple/xnu/blob/10.9/bsd/net/dlil.c#L254
      2:
      https://github.com/opensource-apple/xnu/blob/10.9/bsd/net/if_var.h#L528
      3:
      https://github.com/opensource-apple/xnu/blob/10.9/bsd/net/dlil.c#L188
      4:
      https://github.com/opensource-apple/xnu/blob/10.9/bsd/net/if_var.h#L816

    """
    ifnet_head = profile.get_constant_object(
        "_dlil_ifnet_head",
        target="Pointer",
        target_args=dict(
            target="ifnet"
        )
    )

    for interface in ifnet_head.walk_list("if_link.tqe_next"):
        yield entities.DarwinNetworkInterface(key_obj=interface)


def DarwinUnixSocketGenerator(profile):
    """Walks the global unpcb lists and returns just the sockets.

    Yields:
      DarwinUnixSocket entities.

    See here:
      https://github.com/opensource-apple/xnu/blob/10.9/bsd/kern/uipc_usrreq.c#L121
    """
    for head_const in ["_unp_dhead", "_unp_shead"]:
        lhead = profile.get_constant_object(
            head_const,
            target="unp_head")

        for unp in lhead.lh_first.walk_list("unp_link.le_next"):
            yield entities.DarwinUnixSocket(key_obj=unp.unp_socket)


def DarwinFileprocMultiGenerator(profile):
    """Generates multiple kinds of entities from walking over open handles.

    Currently yields the following:
        DarwinOpenHandle
        DarwinOpenFile
        DarwinUnixSocket
        DarwinInetSocket
        DarwinSocket
    """
    for proc in profile.session.get_entities(entities.DarwinProcess):
        for fd, fileproc, flags in proc.key_obj.get_open_files():
            # First we yield the handle.
            yield entities.DarwinOpenHandle(
                key_obj=fileproc,
                meta=dict(
                    fd=fd,
                    flags=flags,
                    proc=proc.key_obj))

            # Yield the resource:
            resource = fileproc.autocast_fg_data()
            if fileproc.fg_type == "DTYPE_SOCKET":
                if resource.addressing_family in ["AF_INET", "AF_INET6"]:
                    cls = entities.DarwinInetSocket
                elif resource.addressing_family == "AF_UNIX":
                    cls = entities.DarwinUnixSocket
                else:
                    cls = entities.DarwinSocket
            elif fileproc.fg_type == "DTYPE_VNODE":
                cls = entities.DarwinOpenFile
            else:
                # TODO: This could still yield resource?
                continue

            yield cls(key_obj=resource, meta=dict(fileproc=fileproc))


def DarwinPgrpHashProcessGenerator(profile):
    """Generates Process entities using hash of process groups.

    Adapted from legacy pslist plugin's list_using_pgrp_hash.

    Yields:
      DarwinProcess entities.

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
                yield entities.DarwinProcess(key_obj=proc)


def DarwinTaskProcessGenerator(profile):
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
            yield entities.DarwinProcess(key_obj=proc)


def DarwinAllprocProcessGenerator(profile):
    """List all processes by following the _allproc list head.

    Adapted from legacy pslist plugin's list_using_allproc.

    References TBD.
    """
    allproc = profile.get_constant_object(
        "_allproc", target="proclist")
    for proc in allproc.lh_first.p_list:
        yield entities.DarwinProcess(key_obj=proc)


def DarwinPidHashProcessGenerator(profile):
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
                yield entities.DarwinProcess(key_obj=proc)

