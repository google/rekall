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

class a_ent:
    
    def __init__(self, ip, mac, devname):
        self.ip      = ip
        self.mac     = mac
        self.devname = devname

# based off pykdump
# not 100% this works, will need some testing to verify
class linux_arp(linux_common.AbstractLinuxCommand):
    ''' print the ARP table '''
    __name = "arp"


    def calculate(self):

        ntables_ptr = obj.Object("Pointer", offset=self.smap["neigh_tables"], vm=self.addr_space)

        for ntable in linux_common.walk_internal_list("neigh_table", "next", ntables_ptr, self.addr_space):
            yield self.handle_table(ntable)
        
    def handle_table(self, ntable):

        ret = []
        hash_size = ntable.hash_mask

        buckets = obj.Object(theType='Array', offset=ntable.hash_buckets, vm=self.addr_space, targetType='Pointer', count=hash_size)

        for i in xrange(0, hash_size):
            if buckets[i]:
                neighbor = obj.Object("neighbour", offset=buckets[i], vm=self.addr_space)

                ret.append(self.walk_neighbor(neighbor))

        # collapse all lists into one
        return sum(ret, [])

    def walk_neighbor(self, neighbor):
    
        ret = []

        for n in linux_common.walk_internal_list("neighbour", "next", neighbor.v(), self.addr_space):
            
            # get the family from each neighbour in order to work with ipv4 and 6
            family = n.tbl.family

            if family == 2: # AF_INET
                key = obj.Object("unsigned int", offset=n.primary_key.obj_offset, vm=self.addr_space)
                ip = linux_common.ip2str(key)

            elif family == 10: # AF_INET6
                key = obj.Object("in6_addr", offset=n.primary_key.obj_offset, vm=self.addr_space)
                ip  = linux_common.ip62str(key)
            else:
                ip = '?'

            mac     = ":".join(["%.02x" % x for x in n.ha][:n.dev.addr_len]) 
            devname = n.dev.name

            ret.append(a_ent(ip, mac, devname))

        return ret
            
    def render_text(self, outfd, data):

        for arp_list in data:
            for ent in arp_list:
                outfd.write("[{0:42s}] at {1:20s} on {2:s}\n".format(ent.ip, ent.mac, ent.devname))
