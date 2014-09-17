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
Collectors for files, handles, sockets and similar.
"""
__author__ = "Adam Sindelar <adamsh@google.com>"

import datetime

from rekall import identity
from rekall.plugins.collectors.darwin import common


class DarwinHandleCollector(common.DarwinEntityCollector):
    """Collects handles from fileprocs (like OS X lsof is implemented)."""

    collects = [
        "Handle",
        "MemoryObject/type=fileproc",
        "MemoryObject/type=vnode",
        "MemoryObject/type=socket"]

    def collect(self, hint=None):
        manager = self.entity_manager
        for process in manager.find_by_component("Process"):
            proc = process.components.MemoryObject.base_object

            for fd, fileproc, flags in proc.get_open_files():
                fg_data = fileproc.autocast_fg_data()

                # The above can return None if the data in memory is invalid.
                # There's nothing we can do about that, other than rely on
                # collector redundancy. Skip.
                if fg_data == None:
                    continue

                # In addition to yielding the handle, we will also yield the
                # resource it's pointing to, because other collectors rely on
                # memory objects already being out there when they parse them
                # for resource (File/Socket/etc.) specific information.
                resource_identity = identity.BaseObjectIdentity(fg_data)
                handle_identity = identity.BaseObjectIdentity(fileproc)

                yield [
                    manager.Entity(identity=resource_identity),
                    manager.MemoryObject(
                        base_object=fg_data,
                        type=resource_identity.obj_type)]

                yield [
                    manager.Entity(identity=handle_identity),
                    manager.Handle(
                        process=process.identity,
                        fd=fd,
                        flags=flags,
                        resource=resource_identity),
                    manager.MemoryObject(
                        base_object=fileproc,
                        type="fileproc")]


class DarwinSocketCollector(common.DarwinEntityCollector):
    """Searches for all memory objects that are sockets and parses them."""

    _name = "sockets"
    collects = ["Connection", "File/type=socket", "MemoryObject/type=vnode"]

    def collect(self, hint=None):
        manager = self.entity_manager
        for entity in manager.find_by_attribute("MemoryObject/type", "socket"):
            socket = entity["MemoryObject/base_object"]
            family = socket.addressing_family

            # In all these cases, we just reuse the identity of the entity we
            # found, which is most likely a BaseObjectIdentity. This is because
            # there is no more useful way to identify a connection.
            if family in ("AF_INET", "AF_INET6"):
                yield [
                    entity.components.Entity,
                    manager.Connection(
                        addressing_family=family,
                        state=socket.tcp_state,
                        protocols=(
                            "IPv4" if family == "AF_INET" else "IPv6",
                            socket.l4_protocol),
                        src_addr=socket.src_addr,
                        src_bind=socket.src_port,
                        dst_addr=socket.dst_addr,
                        dst_bind=socket.dst_port)]
            elif family == "AF_UNIX":
                if socket.vnode:
                    path = socket.vnode.full_path
                    file_identity = self.session.entities.identify({
                        "File/path": path})
                else:
                    path = None
                    file_identity = None

                yield [
                    entity.components.Entity,
                    manager.Connection(
                        addressing_family="AF_UNIX",
                        src_addr="0x%x" % int(socket.so_pcb),
                        dst_addr="0x%x" % int(socket.unp_conn),
                        protocols=("Unix", socket.unix_type),
                        src_bind=socket.get_socketinfo_attr("unsi_addr"),
                        file_bind=file_identity)]

                # There may be a vnode here - if so, yield it.
                if path:
                    yield [
                        manager.File(
                            path=path,
                            type="socket"),
                        manager.MemoryObject(
                            base_object=socket.vnode.deref(),
                            type="vnode")]
            else:
                yield [
                    entity.components.Entity,
                    manager.Connection(
                        addressing_family=family,
                        protocols=(family,))]


class DarwinFileCollector(common.DarwinEntityCollector):
    """Collects files based on vnodes."""
    collects = ["File", "Permissions", "Event"]
    _name = "files"

    def collect(self, hint=None):
        manager = self.entity_manager
        for entity in manager.find_by_attribute("MemoryObject/type", "vnode"):
            vnode = entity["MemoryObject/base_object"]
            path = vnode.full_path

            components = [
                manager.File(
                    path=path),
                manager.MemoryObject(
                    base_object=vnode,
                    type="vnode")]

            # Parse HFS-specific metadata
            if vnode.v_mount.mnt_vfsstat.f_fstypename == "hfs":
                cattr = vnode.v_data.dereference_as("cnode").c_attr

                # TODO: this currently ignores timezones.
                components.append(manager.Event(
                    created=datetime.datetime.fromtimestamp(cattr.ca_ctime),
                    modified=datetime.datetime.fromtimestamp(cattr.ca_mtime),
                    accessed=datetime.datetime.fromtimestamp(cattr.ca_atime),
                    backed_up=datetime.datetime.fromtimestamp(cattr.ca_btime)))
                components.append(manager.Permissions(
                    owner=manager.identify({
                        "User/uid": cattr.ca_uid,
                        "User/username": None})))

            yield components


class UnpListCollector(common.DarwinEntityCollector):
    """Walks the global unpcb lists and returns the unix sockets.

    See here: https://github.com/opensource-apple/xnu/blob/10.9/bsd/kern/uipc_usrreq.c#L121
    """

    collects = ["MemoryObject/type=socket"]

    def collect(self, hint=None):
        for head_const in ["_unp_dhead", "_unp_shead"]:
            lhead = self.session.get_constant_object(
                head_const,
                target="unp_head")

            for unp in lhead.lh_first.walk_list("unp_link.le_next"):
                yield [
                    self.entity_manager.Entity(
                        identity=identity.BaseObjectIdentity(unp.unp_socket)),
                    self.entity_manager.MemoryObject(
                        base_object=unp.unp_socket,
                        type="socket")]
