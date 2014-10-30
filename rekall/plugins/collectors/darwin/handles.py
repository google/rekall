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

from rekall.entities import collector
from rekall.entities import definitions
from rekall.entities import identity

from rekall.entities.query import expression

from rekall.plugins.collectors.darwin import common
from rekall.plugins.collectors.darwin import zones


class DarwinHandleCollector(common.DarwinEntityCollector):
    """Collects handles from fileprocs (like OS X lsof is implemented)."""

    outputs = [
        "Handle",
        "MemoryObject/type=fileproc",
        "MemoryObject/type=vnode",
        "MemoryObject/type=socket"]
    ingests = expression.ComponentLiteral("Process")

    run_cost = collector.CostEnum.VeryHighCost

    def collect(self, hint=None, ingest=None):
        manager = self.manager
        for process in ingest:
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
                resource_identity = manager.identify({
                    "MemoryObject/base_object": fg_data})
                handle_identity = manager.identify({
                    "MemoryObject/base_object": fileproc})

                yield [
                    resource_identity,
                    definitions.MemoryObject(
                        base_object=fg_data,
                        type=fg_data.obj_type)]

                yield [
                    handle_identity,
                    definitions.Handle(
                        process=process.identity,
                        fd=fd,
                        flags=flags,
                        resource=resource_identity),
                    definitions.MemoryObject(
                        base_object=fileproc,
                        type="fileproc")]


class DarwinSocketZoneCollector(zones.DarwinZoneElementCollector):
    outputs = ["MemoryObject/type=socket"]
    zone_name = "socket"
    type_name = "socket"

    def validate_element(self, socket):
        return socket == socket.so_rcv.sb_so


class DarwinSocketCollector(common.DarwinEntityCollector):
    """Searches for all memory objects that are sockets and parses them."""

    _name = "sockets"
    outputs = [
        "Connection",
        "Handle",
        "Event",
        "Timestamps",
        "File/type=socket",
        "MemoryObject/type=vnode"]

    ingests = expression.Equivalence(
        expression.Binding("MemoryObject/type"),
        expression.Literal("socket"))

    def collect(self, hint=None, ingest=None):
        for entity in ingest:
            socket = entity["MemoryObject/base_object"]
            family = socket.addressing_family

            # Try to guess the process that owns this from the last_pid member.
            # This isn't perfect, because more processes could have handles
            # on the same thing and for older sockets, this may yield the wrong
            # result due to PID reuse - still, it's better than nothing.

            yield [
                self.manager.identify({identity.UniqueIndex(): None}),
                definitions.Event(
                    actor=self.manager.identify({
                        "Process/pid": socket.last_pid}),
                    target=entity.identity,
                    action="accessed",
                    category="latest")]

            if family in ("AF_INET", "AF_INET6"):
                yield [
                    entity.identity,
                    definitions.Named(
                        name=socket.human_name,
                        kind="IP Connection"),
                    definitions.Connection(
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
                    entity.identity,
                    definitions.Named(
                        name=socket.human_name,
                        kind="Unix Socket"),
                    definitions.Connection(
                        addressing_family="AF_UNIX",
                        src_addr="0x%x" % int(socket.so_pcb),
                        dst_addr="0x%x" % int(socket.unp_conn),
                        protocols=("Unix", socket.unix_type),
                        src_bind=socket.get_socketinfo_attr("unsi_addr"),
                        file_bind=file_identity)]

                # There may be a vnode here - if so, yield it.
                if path:
                    yield [
                        definitions.File(
                            path=path,
                            type="socket"),
                        definitions.Named(
                            name=path,
                            kind="Socket"),
                        definitions.MemoryObject(
                            base_object=socket.vnode.deref(),
                            type="vnode")]
            else:
                yield [
                    entity.identity,
                    definitions.Connection(
                        addressing_family=family,
                        protocols=(family,))]


class DarwinFileCollector(common.DarwinEntityCollector):
    """Collects files based on vnodes."""
    outputs = ["File", "Permissions", "Timestamps", "Named"]
    _name = "files"
    ingests = expression.Equivalence(
        expression.Binding("MemoryObject/type"),
        expression.Literal("vnode"))

    def collect(self, hint=None, ingest=None):
        manager = self.manager
        for entity in ingest:
            vnode = entity["MemoryObject/base_object"]
            path = vnode.full_path

            components = [entity.identity,
                          definitions.File(
                              path=path),
                          definitions.Named(
                              name=path)]

            # Parse HFS-specific metadata. We could look at the mountpoint and
            # see if the filesystem is actually HFS, but it turns out that
            # cnodes are also used for stuff like the dev filesystem, so let's
            # just try and see if there's one that looks valid and go with it.
            cnode = vnode.v_data.dereference_as("cnode")
            if cnode.c_rwlock == cnode:
                cattr = vnode.v_data.dereference_as("cnode").c_attr

                # HFS+ stores timestamps as UTC.
                components.append(definitions.Timestamps(
                    created_at=cattr.ca_ctime,
                    modified_at=cattr.ca_mtime,
                    accessed_at=cattr.ca_atime,
                    backup_at=cattr.ca_btime))

            posix_uid = vnode.v_cred.cr_posix.cr_ruid
            if posix_uid:
                components.append(definitions.Permissions(
                    owner=manager.identify({
                        "User/uid": posix_uid})))

            yield components


class UnpListCollector(common.DarwinEntityCollector):
    """Walks the global unpcb lists and returns the unix sockets.

    See here:
        github.com/opensource-apple/xnu/blob/10.9/bsd/kern/uipc_usrreq.c#L121
    """

    outputs = ["MemoryObject/type=socket", "Named/kind=Unix Socket"]

    def collect(self, hint=None, ingest=None):
        for head_const in ["_unp_dhead", "_unp_shead"]:
            lhead = self.session.get_constant_object(
                head_const,
                target="unp_head")

            for unp in lhead.lh_first.walk_list("unp_link.le_next"):
                yield [
                    definitions.MemoryObject(
                        base_object=unp.unp_socket,
                        type="socket"),
                    definitions.Named(
                        kind="Unix Socket")]
