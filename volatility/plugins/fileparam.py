# Volatility
#
# Authors:
# Mike Auty <mike.auty@gmail.com>
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

import volatility.conf as conf
import urllib
import sys
import os
## This is required to ensure that LOCATION is defined here
import volatility.debug as debug
import volatility.addrspace as addrspace #pylint: disable-msg=W0611

config = conf.ConfFactory()

def set_location(_option, _opt_str, filename, parser):
    """Verify the filename actually exists."""
    if not os.path.exists(os.path.abspath(filename)):
        debug.error("The requested file (%s) doesn't exist" % filename)

    parser.values.filename = filename


config.add_option("FILENAME", default = None, action = "callback",
                  callback = set_location, type = 'str',
                  short_option = 'f', nargs = 1,
                  help = "Filename to use when opening an image")
