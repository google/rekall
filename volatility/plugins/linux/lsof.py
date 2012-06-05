# Volatility
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
@author:       Andrew Case
@license:      GNU General Public License 2.0 or later
@contact:      atcuno@gmail.com
@organization: Digital Forensics Solutions
"""

from volatility.plugins.linux import common


class Lsof(common.LinProcessFilter):
    '''Lists open files.'''

    __name = "lsof"

    def lsof(self):
        for task in self.filter_processes():
            fds     = task.files.get_fds()
            max_fds = task.files.get_max_fds()

            fds = self.profile.Object(
                theType = 'Array',
                offset = fds.obj_offset,
                vm = self.kernel_address_space,
                target = 'Pointer', count = max_fds)

            for i in xrange(0, max_fds):
                if fds[i]:
                    filp = self.profile.Object(
                        'file', offset = fds[i], vm = self.kernel_address_space)

                    yield (task, filp, i)

    def get_path(self, task, filep):
        rdentry  = task.fs.get_root_dentry()
        rmnt     = task.fs.get_root_mnt()
        dentry = filep.get_dentry()
        vfsmnt = filep.get_vfsmnt()

        return self.do_get_path(rdentry, rmnt, dentry, vfsmnt)

    # based on __d_path
    # TODO: (deleted) support
    def do_get_path(self, rdentry, rmnt, dentry, vfsmnt):
        ret_path = []

        inode = dentry.d_inode
        while 1:
            # Filenames can be unicode with a maximum length.
            dname = dentry.d_name.name.dereference_as("UnicodeString", length=1024).v()

            if dname != '/':
                ret_path.append(dname)

            if dentry == rdentry and vfsmnt == rmnt:
                break

            if dentry == vfsmnt.mnt_root or dentry == dentry.d_parent:
                if vfsmnt.mnt_parent == vfsmnt:
                    break
                dentry = vfsmnt.mnt_mountpoint
                vfsmnt = vfsmnt.mnt_parent
                continue

            parent = dentry.d_parent

            dentry = parent

        ret_path.reverse()

        ret_val = "/".join(ret_path)

        if ret_val.startswith(("socket:", "pipe:")):
            if ret_val.find("]") == -1:
                ret_val = ret_val[:-1] + "[{0}]".format(inode.i_ino)
            else:
                ret_val = ret_val.replace("/","")

        elif ret_val != "inotify":
            ret_val = '/' + ret_val

        return ret_val

    def render(self, outfd):
        for (task, filp, fd) in self.lsof():
            outfd.write("{0:s}({1}): {2:5d} -> {3:s}\n".format(
                    task.comm, task.pid, fd, self.get_path(
                        task, filp)))
