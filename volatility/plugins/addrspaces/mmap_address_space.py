# Volatility
# Copyright (C) 2011
#
# Authors:
# Michael Cohen <scudette@users.sourceforge.net>
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
#

""" These are standard address spaces supported by Volatility """
import struct
import volatility.addrspace as addrspace
import volatility.debug as debug #pylint: disable-msg=W0611
import urllib
import os
import mmap

class MmapFileAddressSpace(addrspace.BaseAddressSpace):
    """ This is an AS which uses an mmap of a file.

    For this AS to be instantiated, we need

    1) A valid config.LOCATION (starting with file://)

    2) no one else has picked the AS before us
    
    3) base == None (we dont operate on anyone else so we need to be
    right at the bottom of the AS stack.)
    """
    ## We should be the AS of last resort but before the FileAddressSpace
    order = 90

    def __init__(self, base, config, layered = False, **kwargs):
        addrspace.BaseAddressSpace.__init__(self, base, config, **kwargs)
        self.as_assert(base == None or layered, 'Must be first Address Space')
        self.as_assert(config.LOCATION.startswith("file://"),
                       'Location is not of file scheme')

        path = urllib.url2pathname(config.LOCATION[7:])
        self.as_assert(os.path.exists(path), 
                       'Filename must be specified and exist')
        self.name = os.path.abspath(path)
        self.fname = self.name
        self.mode = 'rb'
        if config.WRITE:
            self.mode += '+'
        self.fhandle = open(self.fname, self.mode)
        self.fhandle.seek(0, 2)
        self.fsize = self.fhandle.tell()
        self.offset = 0

        # On 64 bit architectures we can just map the entire image
        # into our process. TODO(scudette): Try to make this work on
        # 32 bit systems by segmenting into several smallish maps.
        self.map = mmap.mmap(self.fhandle.fileno(), self.fsize,
                             access=mmap.ACCESS_READ)

    # Abstract Classes cannot register options, and since this checks
    # config.WRITE in __init__, we define the option here
    @staticmethod
    def register_options(config):
        config.add_option("WRITE", short_option = 'w', action = "store_true",
                          default = False, help = "Enable write support")

    def read(self, addr, length):
        return self.map[addr:addr+length]

    def zread(self, addr, length):
        return self.read(addr, length)

    def get_available_addresses(self):
        # TODO: Explain why this is always fsize - 1?
        yield (0, self.fsize - 1)

    def is_valid_address(self, addr):
        if addr == None:
            return False
        return addr < self.fsize - 1

    def close(self):
        self.map.close()
        self.fhandle.close()

    def write(self, addr, data):
        if not self._config.WRITE:
            return False
        try:
            self.map[addr:addr+len(data)] = data
        except IOError:
            return False
        return True

    def __eq__(self, other):
        return (self.__class__ == other.__class__ and 
                self.base == other.base and self.fname == other.fname)
