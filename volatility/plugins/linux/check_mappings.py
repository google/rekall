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

import linux_proc_maps

class linux_check_mappings(linux_common.AbstractLinuxCommand):

    ''' check for hidden process through the kmem_cache '''

    def calculate(self):
        allocator = linux_kmem_cache.linux_kmem_cache(self.addr_space).get_allocator()

        vma_cache = allocator.walk_kmem_cache("vm_area_struct", self.smap["vm_area_cachep"], 1)

        mm_cache  = allocator.walk_kmem_cache("mm_struct", self.smap["mm_cachep"], 1)

        hidden_vmas = self.gather_vmas(vma_cache, mm_cache)

        for vma in hidden_vmas:

            yield vma


    def gather_vmas(self, vma_cache, mm_cache):
         
        ret = self.check_vma_mmap(vma_cache)

        ret = ret + self.cmp_mm_cache(vma_cache, mm_cache)

        return ret
    
    def cmp_mm_cache(self, vma_cache, mm_cache):

        ret = []

        for vma_addr in vma_cache:

            vma = vma_cache[vma_addr]

            caddr = vma.vm_mm.v()
            
            if not caddr in mm_cache:
                #print "%s -> %x" % (vma.vm_mm.owner.comm, vma.vm_mm.v())
                ret.append(vma)

        return ret

    def check_vma_mmap(self, vma_cache):

        vma_list = linux_proc_maps.linux_proc_maps(self._config).calculate()

        taskvmas = {}
        ret = []

        # get every vma for each task
        for (task, vma) in vma_list:
    
            if not task in taskvmas:
                taskvmas[task] = []

            taskvmas[task].append(vma)
   
        # compare to thos in the vma cache 
        for task in taskvmas:

            allvmas = self.vmas_for_mm(vma_cache, task.mm) 
            
            vmas = taskvmas[task]

            if task.mm != 0xc444cac0:
                continue

            for vma in vmas:
            
                realaddr = vma.obj_offset

                if not realaddr in allvmas:
                    print "vma at %x is hidden" % realaddr
                    ret.append(vma)
                else:
                    allvmas[realaddr] = 0

            # those not in the cache (inverse compare)
            for vma in allvmas:
                if allvmas[vma] == 1:
                    print "vma at %x was found in inverse compare" % vma
                    ret.append(obj.Object("vm_area_struct", offset=vma, vm=self.addr_space))
                
        return ret

    # get the vmas for a specific process
    def vmas_for_mm(self, cache, mm):

        ret = {}

        for vma_addr in cache:

            vma = cache[vma_addr]

            if vma.vm_mm == mm:

                ret[vma_addr] = 1
                
        return ret

    def render_text(self, outfd, data):

        for vma in data:
            if vma.vm_file:
                path = vma.vm_file.get_dentry().d_name.name
                path = linux_common.get_string(path, self.addr_space)
            else:
                path = ""

            if vma.vm_mm:
                print "hidden vma %#x %#x %#x %s" % (vma.vm_mm, vma.vm_start, vma.vm_end, path)



