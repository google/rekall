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

class linux_syscall_table(linux_common.AbstractLinuxCommand):

    ''' verifies the system call table '''
    def __init__(self, config, *args):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args)
        self._config.add_option('ADDRS', short_option = 'I', default = None, help = 'The file containing the anti-rootkit hash database', action = 'store', type = 'str')

    def calculate(self):

        goodaddrs = [int(x, 16) for x in open(self._config.ADDRS, "r").readlines()]
        tblsz = len(goodaddrs)

        tableaddr = self.smap["sys_call_table"] 
    
        table = obj.Object(theType='Array', offset=tableaddr, vm=self.addr_space, targetType='Pointer', count=tblsz)
        
        idx = 0

        for checkaddr in table:
            
            if checkaddr != goodaddrs[idx]:
               yield (idx, checkaddr, goodaddrs[idx])

            idx = idx + 1            
            
    def render_text(self, outfd, data):

        for (idx, badaddr, goodaddr) in data:
            outfd.write("System call %d was %#x instead of %#x!\n" % (idx, badaddr, goodaddr))




