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

import volatility.obj as obj
import linux_common, linux_flags

class fake_root:
    def __init__(self, dentry, vfsmnt):
        self.dentry = dentry
        self.mnt = vfsmnt

class linux_mount(linux_common.AbstractLinuxCommand):

    ''' gathers mounted fs/devices '''

    def calculate(self):

        mntptr = obj.Object("Pointer", offset = self.smap["mount_hashtable"], vm = self.addr_space)

        mnt_list = obj.Object(theType = "Array", offset = mntptr.v(), vm = self.addr_space, targetType = "list_head", count = 512)

        # get each list_head out of the array
        for outerlist in mnt_list:

            for vfsmnt in linux_common.walk_list_head("vfsmount", "mnt_hash", outerlist, self.addr_space):
                yield vfsmnt


    def render_text(self, outfd, data):

        for vfsmnt in data:
            dev_name = linux_common.get_string(vfsmnt.mnt_devname, self.addr_space)

            path = linux_common.do_get_path(vfsmnt.mnt_sb.s_root, vfsmnt.mnt_parent, vfsmnt.mnt_root, vfsmnt, self.addr_space)

            fstype = linux_common.get_string(vfsmnt.mnt_sb.s_type.name, self.addr_space)

            if (vfsmnt.mnt_flags & 0x40) or (vfsmnt.mnt_sb.s_flags & 0x1):
                rr = "ro"
            else:
                rr = "rw"

            mnt_string = self.calc_mnt_string(vfsmnt)

            outfd.write("{0:15s} {1:35s} {2:12s} {3:2s}{4:64s}\n".format(dev_name, path, fstype, rr, mnt_string))

    def calc_mnt_string(self, vfsmnt):

        ret = ""

        for mflag in linux_flags.mnt_flags:
            if mflag & vfsmnt.mnt_flags:
                ret = ret + linux_flags.mnt_flags[mflag]

        return ret











