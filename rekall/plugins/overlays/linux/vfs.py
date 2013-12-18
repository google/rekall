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
@author:       Michael Cohen
@license:      GNU General Public License 2.0 or later
@contact:      scudette@gmail.com
@organization: Google Inc.

This file encapsulates various virtual file system operations for supported
linux versions. The code is basically copied from the kernel sources of the
relevant versions.
"""
from rekall import utils
from rekall.plugins.overlays import basic


class FileName(object):
    """An object to represent a filename."""
    MAX_DEPTH = 15

    def __init__(self, components=None, start_dentry=None):
        self.start_dentry = start_dentry
        self.mount_point = "/"
        self.deleted = False
        if components is None:
            components = []
        self.path_components = components

    def PrependName(self, component):
        self.path_components.insert(0, utils.SmartUnicode(component))

    def FormatName(self, root_dentry):
        # For sockets we need more info.
        if len(self.path_components) >= self.MAX_DEPTH:
            return obj.NoneObject(
                u"Depth exceeded at %s" % "/".join(self.path_components))

        if self.mount_point == "socket:":
            return "{0}/{1}[{2}]".format(
                self.mount_point, root_dentry.d_name.name.deref(),
                self.start_dentry.d_inode.i_ino)

        elif self.mount_point == "pipe:":
            return "{0}[{1}]".format(
                self.mount_point, self.start_dentry.d_inode.i_ino)

        elif self.mount_point == "anon_inode:":
            return u"anon_inode:%s" % self.start_dentry.d_name.name.deref()

        # This is the normal condition for files.
        else:
            return self.__str__()

    def __str__(self):
        if self.deleted:
            deleted = " (deleted) "
        else:
            deleted = ""

        return u"%s%s%s" % (self.mount_point,
                            "/".join(self.path_components), deleted)


class Linux3VFS(object):
    """This is the implementation specific VFS operations.

    Most of the code here is a direct copy of the methods in linux/fs/dcache.c

    http://lxr.free-electrons.com/source/fs/mount.h?v=3.7#L53
    http://lxr.free-electrons.com/source/fs/dcache.c?v=3.7#L2576
    """


    def get_path(self, task, filp):
        """Resolve the dentry, vfsmount relative to this task's chroot.

        Returns:
          An absolute path to the global filesystem mount. (I.e. we do not
          truncate the path at the chroot point as the kernel does).
        """
        return self._prepend_path(filp.f_path, task.fs.root)

    def _real_mount(self, vfsmnt):
        """Return the mount container of the vfsmnt object."""
        return basic.container_of(vfsmnt, "mount", "mnt").reference()

    def _mnt_has_parent(self, mnt):
        return  mnt != mnt.mnt_parent

    def _prepend_path(self, path, root):
        """Return the path of a dentry.

        http://lxr.free-electrons.com/source/fs/dcache.c?v=3.7#L2576
        """
        # Ensure we can not get into an infinite loop here by limiting the
        # depth.
        depth = 0
        dentry = path.dentry
        vfsmnt = path.mnt
        mnt = self._real_mount(vfsmnt)

        result = FileName(start_dentry=dentry)

        # Check for deleted dentry.
        if dentry.d_flags.DCACHE_UNHASHED and not dentry.is_root:
            result.deleted = True

        while (dentry != root.dentry or vfsmnt != root.mnt):
            # Control the depth.
            depth += 1
            if depth >= result.MAX_DEPTH:
                break

            if dentry == vfsmnt.mnt_root or dentry.is_root:
                # Global root?
                if not self._mnt_has_parent(mnt):
                    break

                dentry = mnt.mnt_mountpoint
                mnt = mnt.mnt_parent
                vfsmnt = mnt.mnt.reference()
                continue

            parent = dentry.d_parent
            result.PrependName(dentry.d_name.name.deref())

            dentry = parent

        # When we get here dentry is a root dentry and mnt is the mount point it
        # is mounted on. There are some special mount points we want to
        # highlight.
        result.mount_point = mnt.mnt_mountpoint.d_name.name.deref()

        return result.FormatName(dentry)


class Linux26VFS(Linux3VFS):
    """This is the implementation specific VFS operations.

    Most of the code here is a direct copy of the methods in linux/fs/dcache.c

    http://lxr.free-electrons.com/source/fs/dcache.c?v=2.6.26#L1782
    """

    def get_path(self, task, filp):
        """Resolve the dentry, vfsmount relative to this task's chroot.

        Returns:
          An absolute path to the global filesystem mount. (I.e. we do not
          truncate the path at the chroot point as the kernel does).
        """
        root = task.fs.root.deref()
        # For very old kernels (<=2.6.24) the root member is a dentry not a
        # struct path, so we need to synthesize one.
        if root.obj_type == "dentry":
            root = task.obj_profile.path()
            root.dentry = task.fs.root
            root.mnt = task.fs.rootmnt

        return self.__d_path(filp.f_path, root)

    def d_unhashed(self, dentry):
        return dentry.d_flags.DCACHE_UNHASHED

    def __d_path(self, path, root):
        """A literal copy of the __d_path function from kernel 2.6.26."""
        depth = 0
        dentry = path.dentry
        vfsmnt = path.mnt

        result = FileName(start_dentry=dentry)

        if not dentry.is_root and self.d_unhashed(dentry):
            result.deleted = True

        # Limit the recursion here to avoid getting stuck.
        while depth < result.MAX_DEPTH:
            if (dentry == root.dentry and vfsmnt == root.mnt):
                break

            if (dentry == vfsmnt.mnt_root or dentry.is_root):
                if vfsmnt.mnt_parent == vfsmnt:
                    break

                dentry = vfsmnt.mnt_mountpoint
                vfsmnt = vfsmnt.mnt_parent
                continue

            parent = dentry.d_parent;
            result.PrependName(dentry.d_name.name.deref())

            dentry = parent;

        # When we get here dentry is a root dentry and mnt is the mount point it
        # is mounted on. There are some special mount points we want to
        # highlight.
        result.mount_point = utils.SmartUnicode(
            vfsmnt.mnt_mountpoint.d_name.name.deref())

        return result.FormatName(dentry)
