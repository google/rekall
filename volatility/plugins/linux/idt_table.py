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

class linux_idt_table(linux_common.AbstractLinuxCommand):

    def calculate(self):

        tblsz = 256
        tableaddr = self.smap["idt_table"]
        table = obj.Object(theType='Array', offset=tableaddr, vm=self.addr_space, targetType='_KIDTENTRY', count=tblsz)
        
        addrs = [self.smap[x] for x in self.smap]

        checkidx = list(xrange(0,33)) + [128]

        for i in checkidx:
            
            ent = table[i]
            # from mhl's idt code   
            if ent.ExtendedOffset == 0:
                addr = 0
            else:
                addr = (ent.ExtendedOffset.v() << 16) | ent.Offset.v()         

            if not addr in addrs and addr != 0xc035fa20:
                print "no entry for %d | %x" % (i, addr)
                #pass
 
            
    def render_text(self, outfd, data):

        if not data:
            return

        for (idx, badaddr, goodaddr) in data:
            outfd.write("IDT table index %d was %#x instead of %#x!\n" % (idx, badaddr, goodaddr))




