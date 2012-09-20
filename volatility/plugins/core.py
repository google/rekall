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
import re
import os
import textwrap

from volatility import addrspace
from volatility import args
from volatility import constants
from volatility import registry
from volatility import plugin
from volatility import obj
from volatility import utils


class Info(plugin.Command):
    """Print information about various subsystems."""

    __name = "info"

    standard_options = [("output", " Save output to this file."),
                        ("overwrite", " Must be set to overwrite an output "
                         "file. You can also set this in the session as a "
                         "global setting."),
                        ("renderer", " Use this renderer for the output.")]

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
            if name:
                yield name, cls.name, cls.__doc__.splitlines()[0]

    def profiles(self):
        for name, cls in obj.Profile.classes.items():
            if name:
                yield name, cls.__doc__.splitlines()[0].strip()

    def address_spaces(self):
        for name, cls in addrspaces.BaseAddressSpace.classes.items():
            yield dict(name=name, function=cls.name, definition=cls.__module__)

    def render(self, renderer):
        if self.item is None:
            return self.render_general_info(renderer)
        else:
            return self.render_item_info(self.item, renderer)

    def _split_into_paragraphs(self, string, dedent):
        """Split a string into paragraphs.

        A paragraph is defined as lines of text having the same indentation. An
        empty new line breaks the paragraph.

        The first line in each paragraph is allowed to be indented more than the
        second line.
        """
        paragraph = []
        last_leading_space = 0
        first_line_indent = 0

        for line in string.splitlines():
            line = line[dedent:]

            m = re.match("\s*", line)
            leading_space = len(m.group(0))

            text = line[leading_space:]

            # First line is always included.
            if not paragraph:
                paragraph = [text]
                first_line = True
                first_line_indent = leading_space
                continue

            if first_line and last_leading_space != leading_space:
                if text:
                    paragraph.append(text)

                last_leading_space = leading_space
                first_line = False

            elif leading_space != last_leading_space:
                if paragraph:
                    yield paragraph, first_line_indent

                paragraph = []
                if text:
                    paragraph.append(text)
                last_leading_space = leading_space
                first_line_indent = leading_space
                first_line = True
            else:
                if text:
                    paragraph.append(text)

                first_line = False

        if paragraph:
            yield paragraph, first_line_indent

    def split_into_paragraphs(self, string, dedent=0, wrap=50):
        for paragraph, leading_space in self._split_into_paragraphs(
            string, dedent):
            paragraph = textwrap.wrap("\n".join(paragraph), wrap)
            yield "\n".join([(" " * leading_space + x) for x in paragraph])

    def parse_args_string(self, arg_string):
        """Parses a standard docstring into args and docs for each arg."""
        parameter = None
        doc = ""

        for line in arg_string.splitlines():
            m = re.match("\s+([^\s]+):(.+)", line)
            if m:
                if parameter:
                    yield parameter, doc

                parameter = m.group(1)
                doc = m.group(2)
            else:
                doc += "\n" + line

        if parameter:
            yield parameter, doc

    def render_item_info(self, item, renderer):
        """Render information about the specific item."""
        cls_doc = item.__doc__ or ""

        if isinstance(item, registry.MetaclassRegistry):
            renderer.format("{0}: {1}\n", item.name, cls_doc.splitlines()[0])

            # show the args it takes. Relies on the docstring to be formatted
            # properly.
            doc_string = item.__init__.__doc__ or ""
            doc_string = inspect.cleandoc(doc_string).split("Args:")[0]

            renderer.write("%s\n\n" % doc_string.strip())

            doc_strings = []
            renderer.table_header([('Parameter', 'parameter', '30'),
                                   (' Documentation', 'doc', '70')])

            seen_parameters = set()
            for cls in item.mro():
                cls_doc = cls.__init__.__doc__ or ""
                if self.verbosity > 0:
                    renderer.format("Defined by {0} ({1}):",
                                    cls.__name__, inspect.getfile(cls))

                m = re.search("\n( +)Args:(.+)", cls_doc, re.S|re.M)
                if m:
                    doc_string = m.group(2)
                    dedent = len(m.group(1))
                    for parameter, doc in self.parse_args_string(doc_string):
                        if parameter in seen_parameters: continue

                        seen_parameters.add(parameter)
                        renderer.table_row(parameter,
                                           self._clean_up_doc(doc, dedent))

            # Add the standard help options.
            for parameter, descriptor in self.standard_options:
                renderer.table_row(parameter, self._clean_up_doc(descriptor))

        else:
            # For normal objects just write their docstrings.
            renderer.write(item.__doc__ or "")

    def _clean_up_doc(self, doc, dedent=0):
        clean_doc = []
        for paragraph in self.split_into_paragraphs(
            " " * dedent + doc, dedent=dedent, wrap=70):
            clean_doc.append(paragraph)

        return "\n".join(clean_doc)

    def render_general_info(self, renderer):
        renderer.write(constants.BANNER)
        renderer.section()
        renderer.table_header([('Plugin', 'function', "20"),
                               ('Provider Class', 'provider', '20'),
                               ('Docs', 'docs', '[wrap:50]'),
                               ])

        for cls, name, doc in sorted(self.plugins()):
            renderer.table_row(name, cls, doc)

        renderer.section()
        renderer.table_header([('Profile', 'profile', "20"),
                               ('Docs', 'docs', '[wrap:70]'),
                               ])

        for name, doc in sorted(self.profiles()):
            renderer.table_row(name, doc)



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
                    astype = 'virtual',
                    base_as=self.session.physical_address_space,
                    **kwargs)

                # Set the default address space to the kernel.
                self.session.default_address_space = self.session.kernel_address_space
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
            logging.info("Autodetected %s address space %s", astype, base_as)
        else:
            logging.info("Failed to autodetect %s address space. Try running "
                         "plugin.load_as with a spec.", astype)

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


class LoadPlugins(plugin.Command):
    """Load user provided plugins.

    This probably is only useful after the interactive shell started since you
    can already use the --plugin command line option.
    """

    __name = "load_plugin"

    def __init__(self, path, **kwargs):
        super(LoadPlugins, self).__init__(**kwargs)
        if isinstance(path, basestring):
            path = [path]

        args.LoadPlugins(path)


class Dump(plugin.Command):
    """Hexdump an object or memory location."""

    __name = "dump"

    def __init__(self, target=None, offset=0, width=16, rows=30,
                 suppress_headers=False, **kwargs):
        """Hexdump an object or memory location.

        You can use this plugin repeateadely to keep dumping more data using the
        "p _" (print last result) operation:

        In [2]: dump session.kernel_address_space, 0x814b13b0
        ------> dump(session.kernel_address_space, 0x814b13b0)
        Offset                         Hex                              Data
        ---------- ------------------------------------------------ ----------------
        0x814b13b0 03 00 1b 00 00 00 00 00 b8 13 4b 81 b8 13 4b 81  ..........K...K.

        Out[3]: <volatility.plugins.core.Dump at 0x2967510>

        In [4]: p _
        ------> p(_)
        Offset                         Hex                              Data
        ---------- ------------------------------------------------ ----------------
        0x814b1440 70 39 00 00 54 1b 01 00 18 0a 00 00 32 59 00 00  p9..T.......2Y..
        0x814b1450 6c 3c 01 00 81 0a 00 00 18 0a 00 00 00 b0 0f 06  l<..............
        0x814b1460 00 10 3f 05 64 77 ed 81 d4 80 21 82 00 00 00 00  ..?.dw....!.....

        Args:
          target: The object to dump or an address space.
          offset: The offset to start dumping from.
          width: How many Hex character per line.
          rows: How many rows to dump.
          suppress_headers: If set we do not write the headers.
        """
        super(Dump, self).__init__(**kwargs)
        self.target = target
        self.offset = int(offset)
        self.width = int(width)
        self.rows = int(rows)
        self.suppress_headers = suppress_headers

    def render(self, renderer):
        # Its an object
        if isinstance(self.target, obj.BaseObject):
            data = self.target.obj_vm.zread(self.target.obj_offset,
                                            self.target.size())
            base = self.target.obj_offset
        # Its an address space
        elif isinstance(self.target, addrspace.BaseAddressSpace):
            data = self.target.zread(self.offset, self.width * self.rows)
            base = self.offset

        # If the target is an integer we assume it means an offset to read from
        # the default_address_space.
        elif isinstance(self.target, (int, long)):
            if self.offset == 0:
                self.offset = self.target

            data = self.session.default_address_space.zread(
                self.offset, self.width * self.rows)
            base = self.offset

        # Its a string or something else:
        else:
            data = utils.SmartStr(self.target)
            base = 0

        renderer.table_header([("Offset", "offset", "[addr]"),
                               ("Hex", "hex", "^" + str(3 * self.width)),
                               ("Data", "data", "^" + str(self.width))],
                              suppress_headers=self.suppress_headers)

        offset = 0
        for offset, hexdata, translated_data in utils.Hexdump(
            data, width=self.width):
            renderer.table_row(self.offset + offset, hexdata,
                               "".join(translated_data))

        # Advance the offset so we can continue from this offset next time we
        # get called.
        self.offset += offset
