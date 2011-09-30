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

class linux_route_cache(linux_common.AbstractLinuxCommand):

    ''' lists routing table '''

    def calculate(self):

        mask          = obj.Object("unsigned int",  offset=self.smap["rt_hash_mask"],  vm=self.addr_space)
        rt_pointer    = obj.Object("Pointer", offset=self.smap["rt_hash_table"], vm=self.addr_space)
        rt_hash_table = obj.Object(theType = "Array", offset=rt_pointer, vm=self.addr_space, targetType = "rt_hash_bucket", count=mask)
    
        # rt_do_flush / rt_cache_seq_show
        for i in xrange(0, mask):

            rth = rt_hash_table[i].chain

            if not rth:
                continue
           
            if rth.u.dst.dev:
                name = rth.u.dst.dev.name
            else:
                name = "*"

            dest = rth.rt_dst
            gw   = rth.rt_gateway
           
            yield (name, dest, gw)                

    def render_text(self, outfd, data):

        for (name, dest, gw) in data:
            outfd.write("{0:6s} {1:15s} {2:15s}\n".format(name, linux_common.ip2str(dest), linux_common.ip2str(gw)))

