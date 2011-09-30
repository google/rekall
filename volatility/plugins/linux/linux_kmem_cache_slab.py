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
import sys

class linux_kmem_cache_slab(object):

    ''' implements walking SLAB backed kmem_caches '''
    def __init__(self, addr_space):
        self.addr_space = addr_space


    def process_bitmap(self, struct_name, slab, cache, bitmap, htab, allocated):

        for i in xrange(0, cache.num):

            obj_addr = slab.s_mem.v() + cache.buffer_size.v() * i
            objt = obj.Object(struct_name, offset = obj_addr, vm = self.addr_space)
            setobj = 0

            # a free entry in the bitmap is an allocated object
            if not bitmap[i] and allocated:
                setobj = 1
            elif bitmap[i] and not allocated:
                setobj = 1

            if setobj:
                # fill the hash table with an institated object from the address found int he cache    
                htab[obj_addr] = objt

    def process_slab_list(self, struct_name, cache, list_head, htab, allocated):

        # create bitmap
        bitmap = [0] * cache.num

        for slab in linux_common.walk_list_head("slab", "list", list_head, self.addr_space):

            i = slab.free.v() & 0xffffffff

            bitmap = [0] * cache.num

            while 1:
                if i == 0xffffffff: # BUFCTL_END
                    break

                bitmap[i] = 1

                # slab_bufctl replacment
                slab_array = obj.Object("Array", offset = slab.v() + linux_common.sizeofstruct("slab", self.addr_space.profile), vm = self.addr_space, targetType = "unsigned int", count = i + 1)

                i = slab_array[i]

            self.process_bitmap(struct_name, slab, cache, bitmap, htab, allocated)

    def process_slab(self, struct_name, cache, l3, htab, allocated):

        self.process_slab_list(struct_name, cache, l3.slabs_full, htab, allocated)
        # partial, free
        self.process_slab_list(struct_name, cache, l3.slabs_partial, htab, allocated)

    # returns a hash table keyed by the pointer to each structure
    def walk_kmem_cache(self, struct_name, cache_address, allocated = 1, deref = 1):

        ret = {}

        if not self.addr_space.profile.has_type("kmem_cache"):
            raise AttributeError, "Given profile does not have a kmem_cache structure, please file a bug if the kernel is > 2.6.11"
        elif not self.addr_space.profile.obj_has_member("kmem_cache", "nodelists"):
            raise AttributeError, "struct kmem_cache does not have nodelists member, please file a bug if the kernel is > 2.6.11"

        if deref:         
            cache_address = obj.Object("Pointer", offset = cache_address, vm = self.addr_space)

        cache_obj = obj.Object("kmem_cache", offset = cache_address.v(), vm = self.addr_space)

        # for_each_online_node / node_sates for NUMA only?
        # TODO SMP
      
        l3 = cache_obj.nodelists[0]

        if l3:
            self.process_slab(struct_name, cache_obj, l3, ret, allocated)
        else:
            print "No nodelist[0]???"
            sys.exit(1)

        return ret







