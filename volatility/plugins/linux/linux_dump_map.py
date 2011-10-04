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

import sys
import linux_common
import linux_proc_maps

class linux_dump_map(linux_common.AbstractLinuxCommand):

    ''' gathers process maps '''

    def calculate(self):
        vmas = linux_proc_maps.linux_proc_maps(self._config).calculate()
        for task, vma in vmas:
            # filter on a specific vma starting address
            if vma.vm_file:
                path = []
                yield vma
                #(dentry, inode) = linux_common.file_info(vma.vm_file)
            else:
                length = vma.vm_end - vma.vm_start
                current = vma.vm_start

                while current < vma.vm_end:
                    page = self.addr_space.read(current, 4096)
                    current = current + 4096

    def render_text(self, outfd, data):
        for vma in data:
          outfd.write("%-8x-%-8x\n" % (vma.vm_start&0xffffffff, vma.vm_end&0xffffffff))
