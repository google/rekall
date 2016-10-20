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

import math

from rekall.plugins.linux import common
from rekall.plugins.overlays.linux import vfs


class Container(object):
    """A simple container."""


class Mount(common.LinuxPlugin):
    """Lists the mount points."""
    __name = "mount"

    table_header = [
        dict(name="Device", width=50),
        dict(name="Path", width=50),
        dict(name="Type", width=14),
        dict(name="flags", width=20),
    ]

    def get_mount_points(self):
        if self.profile.get_constant("set_mphash_entries"):
            # Kernel 3.14 starts using an hlist_head instead of a list_head
            mnttype = "mount"
            mount_hashtable_target_type = "hlist_head"
        elif self.profile.has_type("mount"):
            # Kernel 3.3 makes mount_hashtable be a table of struct mount
            mnttype = "mount"
            mount_hashtable_target_type = "list_head"
        else:
            mnttype = "vfsmount"
            mount_hashtable_target_type = "list_head"

        if mount_hashtable_target_type == "list_head":
            # From fs/namespace.c HASH_SIZE
            # http://lxr.free-electrons.com/source/fs/namespace.c?v=3.13#L29
            hashtable_head_len = self.profile.get_obj_size(
                mount_hashtable_target_type)
            page_size = self.kernel_address_space.PAGE_SIZE
            hash_size = 1 << int(math.log(page_size/hashtable_head_len, 2))
            numentries = hash_size

        else:
            # TODO(nop): Finish writing the code
            # 3.14 allows you to customize the number of entries.
            # Note that we could potentially get this value by running the dmesg
            # plugin and parsing the following printk:
            # "Mount-cache hash table entries: XXX"

            # http://lxr.free-electrons.com/source/fs/namespace.c?v=3.14#L2827
            numentries = self.profile.get_constant_object(
                "mhash_entries",
                vm=self.kernel_address_space,
                target="unsigned long").value

            # The followinr code mimics alloc_large_system_hash
            # http://lxr.free-electrons.com/source/mm/page_alloc.c?v=3.14#L5888
            if not numentries:
                nr_kernel_pages = self.profile.get_constant_object(
                    "nr_kernel_pages",
                    vm=self.kernel_address_space,
                    target="unsigned long")
                # XXX Need to finish the calculation
                numentries = 65536

        self.session.logging.debug("numentries: %d", numentries)

        mount_hashtable = self.profile.get_constant_object(
            "mount_hashtable",
            vm=self.kernel_address_space,
            target="Pointer",
            target_args=dict(
                target="Array",
                target_args=dict(
                    count=numentries,
                    target=mount_hashtable_target_type
                )))

        init_task = self.session.profile.get_constant_object(
            "init_task", "task_struct", vm=self.kernel_address_space)
        if not init_task:
            self.session.logging.debug(
              "Unable to obtain the init task. Mounted paths may be incorrect.")

        # Walk the hash table
        for hash in mount_hashtable:
            for mnt in hash.list_of_type(mnttype, "mnt_hash"):

                # Fields have moved between the struct vfsmount and
                # struct mount in different kernel versions.
                vfsmount = mnt.mnt

                # http://lxr.free-electrons.com/source/fs/proc_namespace.c#L92
                # The name of the device is in mnt_devname except when
                # mnt->mnt_sb->s_op->show_devname is defined, in which case
                # the kernel calls it. We do not emulate this call so the
                # device names may differ from those reported in a live system.
                devname = mnt.mnt_devname.deref()

                # A super_block instance
                sb = vfsmount.mnt_sb
                # The name of the filesystem
                fs_type = sb.s_type.name.deref()

                if (not devname.is_valid() or len(str(devname)) == 0 or
                    not fs_type.is_valid() or len(str(fs_type)) == 0):
                    continue

                # http://lxr.free-electrons.com/source/fs/proc_namespace.c#L92
                # Paths get resolved via
                # show_vfsmnt()->seq_path()->d_path()->prepend_path()
                #
                # Note that d_path calls prepend_path only when
                # dentry->d_op->d_name() is not defined. We do not emulate the
                # d_name() codepath, so the resolved mount paths may be a
                # different in rekall than on a live system in these cases.

                path_struct = Container()
                path_struct.dentry = mnt.mnt_root
                path_struct.mnt = vfsmount
                path = vfs.Linux3VFS(self.session.profile).prepend_path(
                    path_struct, init_task.fs.root)
                yield vfs.MountPoint(device=devname,
                                     mount_path=path,
                                     superblock=sb,
                                     flags=vfsmount.mnt_flags,
                                     session=self.session)

    def collect(self):
        for mountpoint in self.get_mount_points():
            flags_string = str(mountpoint.flags)

            # A mountpoint has read-write permissions if it's not readonly.
            if not mountpoint.flags.ro:
                if mountpoint.sb.s_flags & 0x01:
                    additional_flag = "ro"
                else:
                    additional_flag = "rw"
                flags_string = ', '.join([additional_flag, flags_string])

            yield dict(Device=mountpoint.device,
                       Path=mountpoint.name,
                       Type=mountpoint.fstype,
                       flags=flags_string)
