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

import linux_task_list_ps as ltps
import linux_kmem_cache

# we only inherit to get the -p option
class linux_tasklist_kmem_cache(ltps.linux_task_list_ps):

    ''' gathers process through the kmem_cache '''

    def calculate(self):
        allocator = linux_kmem_cache.linux_kmem_cache(self.addr_space).get_allocator()

        tasks = allocator.walk_kmem_cache("task_struct", self.smap["task_struct_cachep"])

        for task_addr in tasks:
            task = tasks[task_addr]

            yield task_addr, task


    def render_text(self, outfd, data):

        for _task_addr, task in data:
            print "%s" % task.comm
