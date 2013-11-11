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
from volatility.plugins.linux import flags


class fake_root(object):
    def __init__(self, dentry, vfsmnt):
        self.dentry = dentry
        self.mnt = vfsmnt



class Mount(common.LinProcessFilter):
    '''Gathers mounted fs/devices.'''

    def calculate(self):

        mntptr = self.profile.Object(
            "Pointer", offset = self.profile.get_constant("mount_hashtable"),
            vm = self.kernel_address_space)

        mnt_list = self.profile.Object(
            theType = "Array", offset = mntptr.v(), vm = self.kernel_address_space,
            targetType = "list_head", count = 512)

        # get each list_head out of the array
        for outerlist in mnt_list:

            for vfsmnt in outerlist.list_of_type("vfsmount", "mnt_hash"):
                yield vfsmnt

    def render(self, outfd):

        for vfsmnt in self.calculate():
            dev_name = vfsmnt.mnt_devname.v()

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











