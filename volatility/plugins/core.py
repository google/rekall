# Volatility
# Copyright (C) 2012 Michael Cohen
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

"""This module implements core plugins."""

__author__ = "Michael Cohen <scudette@gmail.com>"

import logging

from volatility import addrspace
from volatility import plugin


class LoadAddressSpace(plugin.Command):
    """Load address spaces into the session if its not already loaded."""

    __name = "load_as"

    def __init__(self, vas_spec = None, pas_spec = None, **kwargs):
        """Tries to create the address spaces and assigns them to the session.

        An address space specification is a column delimited list of AS
        constructors which will be stacked. For example:

        FileAddressSpace:EWF:JKIA32PagedMemory

        if the specification is "auto" we guess by trying every combintion until
        a virtual AS is obtained.

        Args:
          vas_spec: A Virtual address space specification - a column delimited list of ASs.
          pas_spec: A Physical address space specification.
        """
        super(LoadAddressSpace, self).__init__(**kwargs)
        try:
            if pas_spec and self.session.physical_address_space_spec != pas_spec:
                self.session.physical_address_space = addrspace.AddressSpaceFactory(
                    self.session, specification = pas_spec, astype = 'physical')
                self.session.physical_address_space_spec = pas_spec

            if vas_spec and self.session.virtual_address_space_spec != vas_spec:
                self.session.virtual_address_space = addrspace.AddressSpaceFactory(
                    self.session, specification = vas_spec, astype = 'virtual')
                self.session.virtual_address_space_spec = vas_spec

        except addrspace.ASAssertionError, e:
            logging.error("Could not create address space: %s" % e)


    def GuessAddressSpace(self, astype = 'virtual', **kwargs):
        """Loads an address space by stacking valid ASes on top of each other
        (priority order first)"""
        base_as = obj.NoneObject("Address space not found.")

        # Register all the parameters of all address spaces since we are going to
        # try them all.
        for cls in BaseAddressSpace.classes.values():
            cls.register_options(config)
        config.parse_options()

        error = AddrSpaceError()
        while 1:
            debug.debug("Voting round")
            found = False
            for cls in BaseAddressSpace.classes.values():
                debug.debug("Trying {0} ".format(cls))
                try:
                    base_as = cls(base_as, config, astype=astype, **kwargs)
                    debug.debug("Succeeded instantiating {0}".format(base_as))
                    found = True
                    break
                except ASAssertionError, e:
                    debug.debug("Failed instantiating {0}: {1}".format(cls.__name__, e), 2)
                    error.append_reason(cls.__name__, e)
                    continue
                except Exception, e:
                    debug.debug("Failed instantiating (exception): {0}".format(e))
                    error.append_reason(cls.__name__ + " - EXCEPTION", e)
                    continue

            ## A full iteration through all the classes without anyone
            ## selecting us means we are done:
            if not found:
                break

        return base_as

        
