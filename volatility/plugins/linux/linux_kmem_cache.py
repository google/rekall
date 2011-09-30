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
import linux_kmem_cache_slab
#import linux_kmem_cache_slub

class linux_kmem_cache(object):

    ''' allocator generic kmem_cache interface '''
    def __init__(self, addr_space):
        self.addr_space = addr_space


    # returns an allocator instance, determins which allocator 
    # was in use for the profile
    def get_allocator(self):

        # SLAB only function...

        if "slab" in self.addr_space.profile.types:
            allocator = linux_kmem_cache_slab.linux_kmem_cache_slab(self.addr_space)

        # TODO:slub

        else:
            # ikelos can you change this to debug / error print stuff??
            print "Unable to find suitable allocator!"
            sys.exit(1)


        return allocator









