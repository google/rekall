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
import linux_common
import linux_task_list_ps as ltps
import linux_flags as flags

mn = linux_common.mask_number

class linux_proc_maps(ltps.linux_task_list_ps):

    ''' gathers process maps for linux '''

    MINORBITS = 20
    MINORMASK = ((1 << MINORBITS) - 1)

    def calculate(self):
        tasks = ltps.linux_task_list_ps.calculate(self)

        for task in tasks:
            if task.mm:
                for vma in linux_common.walk_internal_list("vm_area_struct", "vm_next", task.mm.mmap, self.addr_space):
                    yield task, vma

    def render_text(self, outfd, data):

        for task, vma in data:

            mm = task.mm

            if vma.vm_file:
                inode = vma.vm_file.get_dentry().d_inode
                sb = obj.Object("super_block", offset = inode.i_sb, vm = self.addr_space)
                dev = sb.s_dev
                ino = inode.i_ino
                pgoff = vma.vm_pgoff << 12 #fixme 64bit 
                fname = linux_common.get_path(task, vma.vm_file, self.addr_space)
            else:
                (dev, ino, pgoff) = [0] * 3

                if vma.vm_start <= mm.start_brk and vma.vm_end >= mm.brk:
                    fname = "[heap]"

                elif vma.vm_start <= mm.start_stack and vma.vm_end >= mm.start_stack:
                    fname = "[stack]"

                else:
                    fname = ""

            outfd.write("{0:#8x}-{1:#8x} {2:3} {3:10d} {4:#2d}:{5:#2d} {6:#12d} {7}\n".format(
                    mn(vma.vm_start), mn(vma.vm_end), self.format_perms(vma.vm_flags),
                    pgoff, self.MAJOR(dev), self.MINOR(dev), ino, fname))


    def format_perms(self, vma_flags):

        ret = ""
        check = [flags.VM_READ, flags.VM_WRITE, flags.VM_EXEC]
        perms = "rwx"

        for idx in xrange(0, len(check)):
            if vma_flags & check[idx]:
                ret = ret + perms[idx]
            else:
                ret = ret + "-"
        return ret


    def MAJOR(self, num):
        return num >> self.MINORBITS

    def MINOR(self, num):
        return num & self.MINORMASK
