"""These are various utilities for volatility."""
# Volatility
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

import volatility.addrspace as addrspace

#pylint: disable-msg=C0111

def load_as(config, astype = 'virtual', **kwargs):
    """Loads an address space"""
    if astype == 'virtual':
        return config.VIRTUAL_ADDRESS_SPACE or addrspace.GuessAddressSpace(
            config, astype=astype, **kwargs)
    elif astype == 'physical':
        return config.PHYSICAL_ADDRESS_SPACE or addrspace.GuessAddressSpace(
            config, astype=astype, **kwargs)

    return addrspace.GuessAddressSpace(config, astype=astype, **kwargs)

class VolatilityException(Exception):
    """Generic Volatility Specific exception, to help differentiate from other exceptions"""



class CacheRelativeURLException(VolatilityException):
    """Exception for gracefully not saving Relative URLs in the cache"""

def Hexdump(data, width=16):
    """ Hexdump function shared by various plugins """
    for offset in xrange(0, len(data), width):
        row_data = data[offset:offset+width]
        translated_data = [x if ord(x) < 127 and ord(x) > 32 else "." for x in row_data]
        hexdata = " ".join(["{0:02x}".format(ord(x)) for x in row_data])

        yield offset, hexdata, translated_data
