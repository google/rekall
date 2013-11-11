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

import linux_kmem_cache, linux_common
import linux_task_list_ps as task_list_mod

class linux_check_processes(linux_common.AbstractLinuxCommand):

    ''' check for hidden process through the kmem_cache '''

    def calculate(self):
        allocator = linux_kmem_cache.linux_kmem_cache(self.addr_space).get_allocator()

        ctasks      = allocator.walk_kmem_cache("task_struct", self.smap["task_struct_cachep"], 1)

        cache_tasks = ctasks

        all_tasks = self.gather_tasks(cache_tasks)

        for task in all_tasks:

            yield task

    def gather_tasks(self, cache_tasks):
        
        # task_struct->tasks list
        ret = self.check_tasks_list(cache_tasks)
 
        return ret

    def check_tasks_list(self, cache_tasks):

        ret = []

        tlist = task_list_mod.linux_task_list_ps(self._config).calculate()

        # compare to se if hidden from cache
        for task in tlist:
            if not task.obj_offset in cache_tasks:
                #print "adding %s" % task.comm
                ret.append(task.obj_offset)
            else:
                cache_tasks[task.obj_offset] = 0

        # compare to see if cache has extra members
        for addr in cache_tasks:
            if cache_tasks[addr] != 0:
                #print "not zero %x" % addr
                ret.append(addr)


        return ret
    
    def render_text(self, outfd, data):

        for task_addr in data:
            task = obj.Object("task_struct", offset=task_addr, vm=self.addr_space)
            if task.pid == task.tgid and task.state != 64: # TASK_DEAD
                print "hidden task: %s PID: %d UID: %d" % (task.comm, task.pid, task.get_uid())



