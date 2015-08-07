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

from rekall.plugins.collectors.darwin import common


class DarwinHandleCollector(common.DarwinEntityCollector):
    """Collects handles from fileprocs (like OS X lsof is implemented)."""

    _name = "handles"
    outputs = ["Handle",
               "Struct/type=fileproc",
               "Struct/type=vnode",
               "Struct/type=socket"]
    collect_args = dict(processes="has component Process")
    filter_input = True

    run_cost = collector.CostEnum.HighCost

    def collect(self, hint, processes):
        manager = self.manager
        for process in processes:
            proc = process["Struct/base"]

            for fd, fileproc, flags in proc.get_open_files():
                fg_data = fileproc.autocast_fg_data()

                # The above can return None if the data in memory is invalid.
                # There's nothing we can do about that, other than rely on
                # collector redundancy. Skip.
                if not fg_data:
                    continue

                # In addition to yielding the handle, we will also yield the
                # resource it's pointing to, because other collectors rely on
                # memory objects already being out there when they parse them
                # for resource (File/Socket/etc.) specific information.
                resource_identity = manager.identify({
                    "Struct/base": fg_data})
                handle_identity = manager.identify({
                    "Struct/base": fileproc})

                yield [
                    resource_identity,
                    definitions.Struct(
                        base=fg_data,
                        type=fg_data.obj_type)]

                yield [
                    handle_identity,
                    definitions.Handle(
                        process=process.identity,
                        fd=fd,
                        flags=flags,
                        resource=resource_identity),
                    definitions.Struct(
                        base=fileproc,
                        type="fileproc")]


class DarwinFileCollector(common.DarwinEntityCollector):
    """Collects files based on vnodes."""

    outputs = ["File", "Permissions", "Timestamps", "Named"]
    _name = "files"
    collect_args = dict(vnodes="Struct/type is 'vnode'")
    filter_input = True

    def collect(self, hint, vnodes):
        manager = self.manager
        for entity in vnodes:
            vnode = entity["Struct/base"]
            path = vnode.full_path

            components = [entity.identity,
                          definitions.File(
                              path=path),
                          definitions.Named(
                              name=path,
                              kind="File")]

            # Parse HFS-specific metadata. We could look at the mountpoint and
            # see if the filesystem is actually HFS, but it turns out that
            # cnodes are also used for stuff like the dev filesystem, so let's
            # just try and see if there's one that looks valid and go with it.
            cnode = vnode.v_data.dereference_as("cnode")
            if cnode.c_rwlock == cnode:
                cattr = vnode.v_data.dereference_as("cnode").c_attr

                # HFS+ stores timestamps as UTC.
                components.append(definitions.Timestamps(
                    created_at=cattr.ca_ctime.as_datetime(),
                    modified_at=cattr.ca_mtime.as_datetime(),
                    accessed_at=cattr.ca_atime.as_datetime(),
                    backup_at=cattr.ca_btime.as_datetime()))

            posix_uid = vnode.v_cred.cr_posix.cr_ruid
            if posix_uid and posix_uid != 0:
                components.append(definitions.Permissions(
                    owner=manager.identify({
                        "User/uid": posix_uid})))

            yield components
