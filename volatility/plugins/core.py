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
import inspect
import logging

from volatility import addrspace
from volatility import registry
from volatility import plugin
from volatility import obj


class Info(plugin.Command):
    """Print information about various subsystems."""

    __name = "info"

    def __init__(self, item=None, verbosity=0, **kwargs):
        """Display information about a plugin.

        Args:
          item: The plugin class to examine.
          verbosity: How much information to display.
        """
        super(Info, self).__init__(**kwargs)
        self.item = item
        self.verbosity = verbosity

    def plugins(self):
        for name, cls in plugin.Command.classes.items():
            yield dict(name=name, function=cls.name, definition=cls.__module__,
                       doc=cls.__doc__.splitlines()[0])

    def address_spaces(self):
        for name, cls in addrspaces.BaseAddressSpace.classes.items():
            yield dict(name=name, function=cls.name, definition=cls.__module__)

    def render(self, fd):
        if self.item is None:
            return self.render_general_info(fd)
        else:
            return self.render_item_info(self.item, fd)

    def render_item_info(self, item, fd):
        """Render information about the specific item."""
        fd.write("%s:\n\n" % item)

        if isinstance(item, registry.MetaclassRegistry):
            # show the args it takes. Relies of the docstring to be formatted
            # properly.
            if item.__init__.__doc__:
                doc_string = inspect.cleandoc(
                    item.__init__.__doc__).split("Args:")[0]

                fd.write("%s\n\n" % doc_string.strip())

            doc_strings = []
            fd.write("Constructor args:\n" 
                     "-----------------")
            for cls in item.mro():
                try:
                    doc_string = inspect.cleandoc(
                        cls.__init__.__doc__).split("Args:")[1]

                    if doc_string not in doc_strings:
                        doc_strings.append(doc_string)
                        if self.verbosity > 0:
                            fd.write("Defined by %s (%s):" % (
                                    cls.__name__, inspect.getfile(cls)))

                        fd.write("%s" % doc_string)

                except (IndexError, AttributeError):
                    pass

            fd.write("\n\n"
                     "Plugin methods:\n"
                     "---------------\n")
            for name, function in inspect.getmembers(
                item, lambda x: inspect.ismethod(x)):
                if name.startswith("_"): continue

                fd.write("   %s:\n" % name)
                if function.__doc__:
                    fd.write("%s\n\n" % inspect.cleandoc(function.__doc__))


    def render_general_info(self, fd):
        fd.write("Volatility 3.0 alpha\n\n")
        fd.write("Plugins\n"
                 "-------\n"
                 "Function   Provider Class       Definition\n"
                 "---------- -------------------- ----------\n")
        for info in self.plugins():
            fd.write("{function:10} {name:20} {definition}\n  ({doc})\n\n".format(**info))
        


class LoadAddressSpace(plugin.Command):
    """Load address spaces into the session if its not already loaded."""

    __name = "load_as"

    def __init__(self, vas_spec = "auto", pas_spec = "auto", **kwargs):
        """Tries to create the address spaces and assigns them to the session.

        An address space specification is a column delimited list of AS
        constructors which will be stacked. For example:

        FileAddressSpace:EWF:JKIA32PagedMemory

        if the specification is "auto" we guess by trying every combintion until
        a virtual AS is obtained.

        Args:
          vas_spec: A Virtual address space specification - a column delimited
            list of ASs.
          pas_spec: A Physical address space specification.
        """
        super(LoadAddressSpace, self).__init__(**kwargs)
        try:
            # Try to get a physical address space.
            if pas_spec == "auto":
                self.session.physical_address_space = self.GuessAddressSpace(
                    astype = 'physical', **kwargs)
            else:
                self.session.physical_address_space = addrspace.AddressSpaceFactory(
                    self.session, specification = pas_spec, astype = 'physical')

            if vas_spec == "auto":
                self.session.kernel_address_space = self.GuessAddressSpace(
                    astype = 'virtual', **kwargs)
            else:
                self.kernel_address_space = addrspace.AddressSpaceFactory(
                    self.session, specification = vas_spec, astype = 'virtual')

        except addrspace.ASAssertionError, e:
            logging.error("Could not create address space: %s" % e)


    def GuessAddressSpace(self, astype = 'physical', **kwargs):
        """Loads an address space by stacking valid ASes on top of each other
        (priority order first).        
        """
        logging.debug("Guess %s address space", astype)

        base_as = obj.NoneObject("Address space not found.")

        error = addrspace.AddrSpaceError()
        while 1:
            logging.debug("Voting round")
            found = False
            for cls in addrspace.BaseAddressSpace.classes.values():
                logging.debug("Trying %s ", cls)
                try:
                    base_as = cls(base_as, self.session, astype=astype, **kwargs)
                    logging.debug("Succeeded instantiating %s", base_as)
                    found = True
                    break
                except addrspace.ASAssertionError, e:
                    logging.debug("Failed instantiating %s: %s", cls.__name__, e)
                    error.append_reason(cls.__name__, e)
                    continue
                except Exception, e:
                    logging.debug("Failed instantiating (exception): %s", e)
                    error.append_reason(cls.__name__ + " - EXCEPTION", e)
                    continue

            ## A full iteration through all the classes without anyone
            ## selecting us means we are done:
            if not found:
                break

        # Virtual AS's must have a dtb:
        if astype == 'virtual' and not getattr(base_as, "dtb", None):
            base_as = None

        if base_as:
            logging.info("Autodetected %s address space %s\n", astype, base_as)
        else:
            logging.info("Failed to autodetect %s address space. Try running "
                         "plugin.load_as with a spec.\n", astype)

        return base_as

