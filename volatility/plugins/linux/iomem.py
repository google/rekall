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

class linux_iomem(linux_common.AbstractLinuxCommand):

    ''' mimics /proc/iomem '''
    
    def print_resource(self, io_ptr, ischild=0):

        if not io_ptr:
            #print "null"
            return

        io_res = obj.Object("resource", offset=io_ptr, vm=self.addr_space)

        name = linux_common.get_string(io_res.name, self.addr_space)

        print "\t" * ischild + name

        self.print_resource(io_res.child, 1)
        self.print_resource(io_res.sibling, 0)

    def calculate(self):

        io_ptr = self.smap["iomem_resource"]

        self.print_resource(io_ptr)

    def render_text(self, outfd, data):

        pass 
