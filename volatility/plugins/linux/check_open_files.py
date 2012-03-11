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

import volatility.obj as obj
import linux_kmem_cache, linux_common

import linux_task_list_ps    as list_task_mod
import linux_list_open_files as list_files_mod
import linux_proc_maps       as list_maps_mod

class linux_check_open_files(linux_common.AbstractLinuxCommand):

    ''' check for hidden process through the kmem_cache '''

    def calculate(self):
        allocator  = linux_kmem_cache.linux_kmem_cache(self.addr_space).get_allocator()
        filp_cache = allocator.walk_kmem_cache("file", self.smap["filp_cachep"], 1)

        all_files = self.gather_files()

        #print "c: %d a: %d" % (len(filp_cache), len(all_files))

        # files hidden from the cache
        for filp in all_files:
        
            if not filp in filp_cache:
                yield filp

        # files hidden from swap, memory maps, or open files
        for filp in filp_cache:

            if not filp in all_files:
                yield filp

            
        #for filp in hidden_files:

        #    yield vma

    def gather_files(self):

        fhash = {}

        files = self.gather_task_files()

        files = files + self.gather_swap_files()

        for f in files:
            fhash[f] = 1        

        #print "before: %d after: %d" % (len(files), len(fhash))

        return fhash

    def gather_swap_files(self):

        nr_swap   = obj.Object("int",              offset=self.smap["nr_swapfiles"], vm=self.addr_space)
        swap_info = obj.Object(theType="Array", targetType="swap_info_struct", offset=self.smap["swap_info"], vm=self.addr_space, count=nr_swap)
        
        ret = []

        for i in xrange(0, nr_swap):

            s = swap_info[i]
        
            ret.append(self.get_val(s.swap_file))

        return ret

    def get_val(self, f):
        
        return f.v()

    def gather_task_files(self):
         
        allret = []

        all_tasks = list_task_mod.linux_task_list_ps(self._config).calculate()
    
        for task in all_tasks:

            ret = self.do_gather_task_files(task)
            ret = ret + self.do_gather_vmas(task)           
 
            # pull open files from threads as well as tasks
            for thread in linux_common.walk_list_head("task_struct", "thread_group", task.thread_group, self.addr_space):

                ret = ret + self.do_gather_task_files(thread)
                ret = ret + self.do_gather_vmas(thread)

            #print "task %s %d has %d filps" % (task.comm, task.pid, len(ret))

            allret = allret + ret

        return allret

    def do_gather_task_files(self, task):

        ret = [self.get_val(f) for (t, f, i, addr) in list_files_mod.linux_list_open_files(self._config).get_fd_info(task)]
        
        return ret

    def do_gather_vmas(self, task):

        ret = []

        for (task_, vma) in list_maps_mod.linux_proc_maps(self._config).get_vma_info(task):

            if vma.vm_file:
                ret.append(self.get_val(vma.vm_file))

        return ret

    def render_text(self, outfd, data):

        for f_addr in data:
            f = obj.Object("file", offset=f_addr, vm=self.addr_space)
            s = linux_common.get_string(f.get_dentry().d_name.name, self.addr_space)
            if len(s) > 0:
                print "hidden: %s" % s


