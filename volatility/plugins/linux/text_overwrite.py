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

import hashlib, sys

class linux_text_overwrite(linux_common.AbstractLinuxCommand):

    ''' checks in-memory code sections against a whilelist '''
    def __init__(self, config, *args):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args)
        self._config.add_option('HASHES', short_option = 'I', default = None, help = 'The file containing the anti-rootkit hash database', action = 'store', type = 'str')

    def calculate(self):
    
        hashes = open(self._config.HASHES, "r")

        for line in hashes.readlines():

            (name, addr, size, digest, adigest) = line.replace(" ","").strip("\r\n").split("|")

            addr = int(addr)
            size = int(size)

            membytes = self.addr_space.read(addr, size)

            memdigest = hashlib.md5(membytes).hexdigest()

            if memdigest != digest and adigest == "0":
                print "Overwritten code detected for function %.50s! Hashes: %s | %s | %s" % (name, str(digest), str(adigest), str(memdigest))
                #pass
            else:
                pass
                #print "match %s" % name

    def render_text(self, outfd, data):

        pass

