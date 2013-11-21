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
relevant sections.
"""
from volatility import utils
from volatility.plugins.overlays import basic


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
        return basic.container_of(vfsmnt, "mount", "mnt")

    def _mnt_has_parent(self, mnt):
        return  mnt != mnt.mnt_parent

    def _prepend_path(self, path, root):
        """Return the path of a dentry.

        http://lxr.free-electrons.com/source/fs/dcache.c?v=3.7#L2576
        """
        dentry = path.dentry
        vfsmnt = path.mnt
        mnt = self._real_mount(vfsmnt)

        path_components = []

        # Check for deleted dentry.
        if dentry.d_flags.DCACHE_UNHASHED and not dentry.is_root:
            return " (deleted) "

        while dentry != root.dentry or vfsmnt != root.mnt:
            if dentry == vfsmnt.mnt_root or dentry.is_root:
                # Global root?
                if not self._mnt_has_parent(mnt):
                    break

                dentry = mnt.mnt_mountpoint
                mnt = mnt.mnt_parent
                vfsmnt = mnt.mnt
                continue

            parent = dentry.d_parent

            component = utils.SmartUnicode(dentry.d_name.name.deref())
            path_components = [component] + path_components

            dentry = parent

        result = '/'.join(filter(None, path_components))

        if result.startswith(("socket:", "pipe:")):
            if result.find("]") == -1:
                result += ":[{0}]".format(inode.i_ino)

        elif result != "inotify":
            result = '/' + result

        return result


class Linux26VFS(object):
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

    def prepend_name(self, components, d_name):
        components.insert(0, utils.SmartUnicode(d_name.name.deref()))

    def __d_path(self, path, root):
        dentry = path.dentry
        vfsmnt = path.mnt
        is_deleted = False

        components = []

        if not dentry.is_root and self.d_unhashed(dentry):
            is_deleted = True

        while 1:
            if (dentry == root.dentry and vfsmnt == root.mnt):
                break

            if (dentry == vfsmnt.mnt_root or dentry.is_root):
                if vfsmnt.mnt_parent == vfsmnt:
                    break

                dentry = vfsmnt.mnt_mountpoint
                vfsmnt = vfsmnt.mnt_parent
                continue

            parent = dentry.d_parent;
            self.prepend_name(components, dentry.d_name)

            dentry = parent;

        result = "/" + "/".join(components)

        if is_deleted:
            result += " (deleted)"

        return result
