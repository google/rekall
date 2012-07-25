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
import pdb
import os

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
        fd.write("%s:\n%s\n\n" % (item, item.__doc__))

        if isinstance(item, registry.MetaclassRegistry):
            # show the args it takes. Relies on the docstring to be formatted
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



class LoadAddressSpace(plugin.ProfileCommand):
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
                self.session.physical_address_space = self.AddressSpaceFactory(
                    specification=pas_spec, astype='physical')

            if vas_spec == "auto":
                self.session.kernel_address_space = self.GuessAddressSpace(
                    astype = 'virtual', base_as=self.session.physical_address_space,
                    **kwargs)
            else:
                self.kernel_address_space = self.AddressSpaceFactory(
                    specification=vas_spec, astype='virtual')

        except addrspace.ASAssertionError, e:
            logging.error("Could not create address space: %s" % e)


    def GuessAddressSpace(self, session=None, astype = 'physical', base_as=None,
                          **kwargs):
        """Loads an address space by stacking valid ASes on top of each other
        (priority order first).
        """
        logging.debug("Guess %s address space", astype)

        base_as = base_as or obj.NoneObject("Address space not found.")
        error = addrspace.AddrSpaceError()

        address_spaces = sorted(addrspace.BaseAddressSpace.classes.values(),
                                key=lambda x: x.order)

        while 1:
            logging.debug("Voting round")
            found = False
            for cls in address_spaces:
                logging.debug("Trying %s ", cls)
                try:
                    base_as = cls(base=base_as, session=self.session,
                                  astype=astype, profile=self.profile, **kwargs)
                    logging.debug("Succeeded instantiating %s", base_as)
                    found = True
                    break
                except (AssertionError, addrspace.ASAssertionError), e:
                    logging.debug("Failed instantiating %s: %s", cls.__name__, e)
                    error.append_reason(cls.__name__, e)
                    continue
                except Exception, e:
                    logging.error("Fatal Error: %s", e)
                    if self.session.debug:
                        pdb.post_mortem()
                    return

            ## A full iteration through all the classes without anyone
            ## selecting us means we are done:
            if not found:
                break

        # Virtual AS's must have a dtb:
        if astype == 'virtual' and getattr(base_as, "dtb", None) is None:
            base_as = None

        if base_as:
            logging.info("Autodetected %s address space %s\n", astype, base_as)
        else:
            logging.info("Failed to autodetect %s address space. Try running "
                         "plugin.load_as with a spec.\n", astype)

        return base_as

    def AddressSpaceFactory(self, specification = '', astype = 'virtual'):
        """Build the address space from the specification.

        Args:
           specification: A column separated list of AS class names to be stacked.
        """
        base_as = None
        for as_name in specification.split(":"):
            as_cls = addrspace.BaseAddressSpace.classes.get(as_name)
            if as_cls is None:
                raise addrspace.Error("No such address space %s" % as_name)

            base_as = as_cls(base=base_as, session=self.session, astype=astype,
                             **kwargs)

        return base_as



class HexDumper(plugin.Command):
    """Hexdump a region of memory."""

    __name = "hexdump"

    fd = None

    def __init__(self, offset=0, vm=None, width=16, length=25, **kwargs):
        """Hexdump a region of memory.

        Note that this plugin can be reused to keep dumping from where it was left off last time. Each call to render() resumes from the last place. This is useful for the shell:

        In[0]: vol plugins.hexdump, offset=10

        ....
        In[1]: _.render()
        ....  Resumes to dump another page.

        Args:
          - offset: Where to start from.
          - vm: The address space to use. If not specified we use session.kernel_address_space.
          - width: The width of the hexdump.
          - length: The number of lines to dump.
        """
        super(HexDumper, self).__init__(**kwargs)
        self.offset = offset
        self.vm = vm or self.session.kernel_address_space
        self.width = width
        self.length = length

    def render(self, fd=None):
        if fd is None:
            fd = self.fd

        self.fd = fd
        for row in xrange(self.length):
            row_data = self.vm.zread(self.offset, self.width)

            translated_data = [x if ord(x) < 127 and ord(x) > 32 else "." for x in row_data]
            translated_data = "".join(translated_data)

            hexdata = " ".join(["{0:02x}".format(ord(x)) for x in row_data])

            fd.write("{0:016X} | {1} | {2}\n".format(
                    self.offset, hexdata, translated_data))
            self.offset += self.width


class DirectoryDumperMixin(object):
    """A mixin for plugins that want to dump files to a directory."""

    @classmethod
    def args(cls, parser):
        """Declare the command line args we need."""
        super(DirectoryDumperMixin, cls).args(parser)
        parser.add_argument("--dump-dir", required=True,
                            help="Path suitable for dumping files (required).")

    def __init__(self, dump_dir=None, **kwargs):
        super(DirectoryDumperMixin, self).__init__(**kwargs)

        self.dump_dir = dump_dir or self.session.dump_dir
        self.check_dump_dir(self.dump_dir)

    def check_dump_dir(self, dump_dir=None):
        if not dump_dir:
            raise plugin.PluginError("Please specify a dump directory.")

        if not os.path.isdir(dump_dir):
            raise plugin.PluginError("%s is not a directory" % self.dump_dir)


class Null(plugin.Command):
    """This plugin does absolutely nothing.

    It is used to measure startup overheads.
    """
    __name = "null"

    def render(self, outfd):
        pass


