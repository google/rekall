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
import volatility.plugins.linux_task_list_ps as ltps

class linux_dump_map(ltps.linux_task_list_ps):

    ''' gathers process maps '''
    def __init__(self, config, *args):
        #linux_coimmon.AbstractLinuxCommand.__init__(self, config, *args)
        ltps.linux_task_list_ps.__init__(self, config, *args)

        self._config.add_option('VMA',        short_option = 's', default = None, help = 'Filter by VMA starting address', action = 'store', type = 'long')
        self._config.add_option('OUTPUTFILE', short_option = 'O', default = None, help = 'Output File', action = 'store', type = 'str')
    
    def read_addr_range(self, task, start, end):

        pagesize = 4096 # TODO 64bit

        tmp_dtb = self.addr_space.vtop(task.mm.pgd)

        # set the as with our new dtb so we can read from userland
        proc_as = self.addr_space.__class__(self.addr_space.base, self.addr_space.get_config(), dtb = tmp_dtb)

        # xrange doesn't support longs :(
        while start < end:
            
            page  = proc_as.read(start, pagesize)

            yield page

            start = start + pagesize

    def calculate(self):
        vmas = linux_proc_maps.linux_proc_maps(self._config).calculate()

        outfile = open(self._config.OUTPUTFILE, "wb+")

        for (task, vma) in vmas:

            if not self._config.VMA or vma.vm_start == self._config.VMA:
            
                for page in self.read_addr_range(task, vma.vm_start, vma.vm_end):
                    outfile.write(page)

        outfile.close()

    def render_text(self, outfd, data):

        pass


