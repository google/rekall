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

class r_ent:

    def __init__(self, dest, gw, mask, devname):
        self.dest = dest
        self.gw   = gw
        self.mask = mask
        self.devname = devname
            
# TODO needs testing!!!
# based on code from pykdump
class linux_route(linux_common.AbstractLinuxCommand):
  
    ''' lists routing table '''

    def calculate(self):
        fib_tables = self.get_fib_tables()

        for fib_table in fib_tables:
            for rent in self.get_fib_entries(fib_table):
                yield (rent.dest, rent.gw, rent.mask, rent.devname)
        
    def render_text(self, outfd, data):

        outfd.write("{0:15s} {1:15s} {2:15s} {3:s}\n".format("Destination", "Gateway", "Mask", "Interface"))
        for dest, gw, mask, devname in data:
            outfd.write("{0:15s} {1:15s} {2:15s} {3:s}\n".format(linux_common.ip2str(dest), linux_common.ip2str(gw), linux_common.ip2str(mask), devname))

    def get_fib_entries(self, table):
        
        fn_hash   = obj.Object("fn_hash", offset=table.tb_data.obj_offset, vm=self.addr_space)
        zone_list = fn_hash.fn_zone_list

        for r in self.walk_zone_list(zone_list):
            yield r

    def walk_zone_list(self, zone_list):
        
        for fn_zone in linux_common.walk_internal_list("fn_zone", "fz_next", zone_list , self.addr_space):
            
            mask       = fn_zone.fz_mask
            hash_head  = fn_zone.fz_hash
            array_size = fn_zone.fz_divisor
        
            head_array = obj.Object(theType="Array", offset=hash_head, vm=self.addr_space, targetType='hlist_head', count=array_size) 
            
            for head_list in head_array:
                
                first = head_list.first
                if first:
                    for dest, gw, devname in self.parse_fib_node(first):
                        yield r_ent(dest, gw, mask, devname)

    def parse_fib_node(self, first):
        
        for fnptr in linux_common.walk_internal_list("hlist_node", "next", first, self.addr_space):

            fnode = obj.Object("fib_node", offset=fnptr.v(), vm=self.addr_space)

            for alias in linux_common.walk_list_head("fib_alias", "fa_list", fnode.fn_alias, self.addr_space):

                dest  = fnode.fn_key
                fi    = alias.fa_info
            
                if fi:
                    if fi.fib_nh[0].nh_dev:
                        devname = fi.fib_nh[0].nh_dev.name
                    else:
                        devname = '*'

                    gw = fi.fib_nh[0].nh_gw
                else:
                    gw = 0
                    devname = ""    

                yield (dest, gw, devname)    
  
    def get_fib_table(self):

        # get pointer to table
        if "fib_table_hash" in self.smap:
            fib_table_ptr = self.smap["fib_table_hash"]

        elif "init_net" in self.smap:
            
            init_net     = obj.Object("net", offset=self.smap["init_net"], vm=self.addr_space) 
            fib_table_ptr = obj.Object("Pointer", offset=init_net.ipv4.fib_table_hash, vm=self.addr_space)
                
        else:
            # ikelos what is the proper expection to raise?
            print "BAD: Cannot find fib_table_hash.."
            sys.exit(1)

        # get the size
        if "fib_table_hash_symbol" in self.smap: # TODO "if fib_table_hash symbol is an array"
            fib_tbl_sz = -1 # BUG make it size of the array
            raise AttributeError, "please file a bug with kernel version and distribution that triggered this message"

        elif self.profile.obj_has_member("fib_table","fib_power"):
            fib_tbl_sz = 256

        else:
            fib_tbl_sz = 2


        fib_table = obj.Object(theType='Array', offset=fib_table_ptr, \
            vm=self.addr_space, targetType='hlist_head', count=fib_tbl_sz)

        return (fib_table, fib_tbl_sz)

    def get_fib_tables(self):

        ret = []
        
        if "fib_tables" in self.smap:
            fib_tables    = obj.Object(theType = "Array", offset=self.smap["fib_tables"], \
                   vm=self.addr_space, targetType='fib_table', count=256)
            ret = [f for f in fib_tables if f]

        else:
            
            (fib_table, tbl_sz) = self.get_fib_table()

            for i in xrange(0, tbl_sz):
                fb = fib_table[i]

                if fb and fb.first:
                    for tb in linux_common.walk_list_head("fib_table", "tb_hlist", fb.first, self.addr_space):
                        ret.append(tb)
                    
        return ret 
                      




 
