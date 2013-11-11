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

class linux_fdtable_defer(linux_common.AbstractLinuxCommand):

    ''' gathers de-allocated fdtables '''

    def calculate(self):
        
        for i, fdt_defer in linux_common.walk_per_cpu_var(self, "fdtable_defer_list", "fdtable_defer"):
            print "%x" % fdt_defer.next.v()
         
    def render_text(self, outfd, data):
        pass












