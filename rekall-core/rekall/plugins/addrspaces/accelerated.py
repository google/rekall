# Copyright 2013 Google Inc. All Rights Reserved.
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

"""The module provides alternate implementations utilizing C extension modules.
"""

__author__ = "scudette@google.com (Michael Cohen)"
import logging
import os

from rekall import support
from rekall.plugins.addrspaces import amd64

class AcceleratedAMD64PagedMemory(amd64.AMD64PagedMemory):
    """An accelerated AMD64 address space."""

    def __init__(self, **kwargs):
        super(AcceleratedAMD64PagedMemory, self).__init__(**kwargs)
        self._delegate = support.AMD64PagedMemory(self.base, int(self.dtb))

    def read(self, offset, length):
        return self._delegate.read(int(offset), int(length))

    def vtop(self, address):
        return self._delegate.vtop(int(address))

    def get_available_addresses(self):
        for virt, offset, _ in self._delegate.get_available_addresses():
            yield virt, offset


if os.environ.get("FAST"):
    logging.info("Installing accelerated address spaces.")
    # Replace the original implementation with the accelerated one.
    AcceleratedAMD64PagedMemory.classes[
        "AMD64PagedMemory"] = AcceleratedAMD64PagedMemory

