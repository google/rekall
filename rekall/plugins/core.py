# Rekall Memory Forensics
# Copyright (C) 2012 Michael Cohen
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

"""This module implements core plugins."""

__author__ = "Michael Cohen <scudette@gmail.com>"

import inspect
import logging
import pdb
import re
import os
import textwrap

from rekall import addrspace
from rekall import args
from rekall import config
from rekall import constants
from rekall import io_manager
from rekall import registry
from rekall import plugin
from rekall import obj
from rekall import utils


class DummyParser(object):
    """A dummy object used to collect all defined args."""

    def __init__(self):
        self.args = {}

    def add_argument(self, short_option, long_opt="", help=None, **_):
        name = long_opt.lstrip("-") or short_option.lstrip("-")
        self.args[name] = help or ""


class Info(plugin.Command):
    """Print information about various subsystems."""

    __name = "info"

    standard_options = [("renderer", "Use this renderer for the output.")]

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
                doc = cls.__doc__ or " "
                yield name, cls.name, doc.splitlines()[0]

    def profiles(self):
        for name, cls in obj.Profile.classes.items():
            if self.verbosity == 0 and not cls.metadata("os"):
                continue

            if name:
                yield name, cls.__doc__.splitlines()[0].strip()

    def address_spaces(self):
        for name, cls in addrspace.BaseAddressSpace.classes.items():
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

            m = re.match(r"\s*", line)
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
            m = re.match(r"\s+([^\s]+):(.+)", line)
            if m:
                if parameter:
                    yield parameter, doc

                parameter = m.group(1)
                doc = m.group(2)
            else:
                doc += "\n" + line

        if parameter:
            yield parameter, doc

    def get_default_args(self, item=None):
        if item is None:
            item = self.item

        dummy_parser = DummyParser()
        item.args(dummy_parser)
        for x, y in dummy_parser.args.items():
            yield x, self._clean_up_doc(y)

    def render_item_info(self, item, renderer):
        """Render information about the specific item."""
        cls_doc = inspect.cleandoc(item.__doc__ or " ")
        init_doc = inspect.cleandoc(
            (item.__init__.__doc__ or " ").split("Args:")[0])

        if isinstance(item, registry.MetaclassRegistry):
            # show the args it takes. Relies on the docstring to be formatted
            # properly.
            doc_string = cls_doc + init_doc
            doc_string += (
                "\n\nLink:\n"
                "http://epydocs.rekall.googlecode.com/git/%s.%s-class.html"
                "\n\n" % (item.__module__, item.__name__))

            renderer.write(doc_string)

            renderer.table_header([('Parameter', 'parameter', '30'),
                                   (' Documentation', 'doc', '70')])
            for parameter, doc in self.get_default_args(item):
                renderer.table_row(parameter, doc)

            # Add the standard help options.
            for parameter, descriptor in self.standard_options:
                renderer.table_row(parameter, self._clean_up_doc(descriptor))

        else:
            # For normal objects just write their docstrings.
            renderer.write(item.__doc__ or " ")

        renderer.write("\n")

    def _clean_up_doc(self, doc, dedent=0):
        clean_doc = []
        for paragraph in self.split_into_paragraphs(
            " " * dedent + doc, dedent=dedent, wrap=70):
            clean_doc.append(paragraph)

        return "\n".join(clean_doc)

    def render_profile_info(self, renderer):
        for path in self.session.state.profile_path:
            manager = io_manager.Factory(path)
            renderer.section()
            renderer.format("Profile Repository {0}\n\n", path)
            renderer.table_header([('Profile', 'profile', "40"),
                                   ('Docs', 'docs', '[wrap:70]'),
                                   ])

            try:
                # If the repository contains a proper metadata list we show it.
                repository_metadata = manager.GetData("metadata")
                if repository_metadata:
                    for name, profile_metadata in sorted(
                        repository_metadata.get("inventory", {}).items()):

                        renderer.table_row(
                            name, profile_metadata.get("description", ""))
            except IOError:
                # Otherwise we just list the files in the repository.
                for name in sorted(manager.ListFiles()):
                    renderer.table_row(name)


    def render_general_info(self, renderer):
        renderer.write(constants.BANNER)
        renderer.section()
        renderer.table_header([('Command', 'function', "20"),
                               ('Provider Class', 'provider', '20'),
                               ('Docs', 'docs', '[wrap:50]'),
                               ])

        for cls, name, doc in sorted(self.plugins(), key=lambda x: x[1]):
            renderer.table_row(name, cls, doc)

        self.render_profile_info(renderer)


class FindDTB(plugin.PhysicalASMixin, plugin.ProfileCommand):
    """A base class to be used by all the FindDTB implementation."""
    __abstract = True

    def dtb_hits(self):
        """Yields hits for the DTB offset."""
        return []

    def VerifyHit(self, hit):
        """Verify the hit for correctness, yielding an address space."""
        return self.CreateAS(hit)

    def address_space_hits(self):
        """Finds DTBs and yields virtual address spaces that expose kernel.

        Yields:
          BaseAddressSpace-derived instances, validated using the
          verify_address_space() method..
        """
        for hit in self.dtb_hits():
            address_space = self.VerifyHit(hit)
            if address_space is not None:
                yield address_space

    def CreateAS(self, dtb):
        """Creates an address space from this hit."""
        address_space_cls = self.GetAddressSpaceImplementation()
        try:
            return address_space_cls(
                base=self.physical_address_space,
                dtb=dtb, session=self.session,
                profile=self.profile)
        except IOError:
            return None

    def GetAddressSpaceImplementation(self):
        """Returns the correct address space class for this profile."""
        # The virtual address space implementation is chosen by the profile.
        architecture = self.profile.metadata("arch")
        if architecture == "AMD64":
            as_class = addrspace.BaseAddressSpace.classes['AMD64PagedMemory']

        # PAE profiles go with the pae address space.
        elif architecture == "I386" and self.profile.metadata("pae"):
            as_class = addrspace.BaseAddressSpace.classes['IA32PagedMemoryPae']

        else:
            as_class = addrspace.BaseAddressSpace.classes['IA32PagedMemory']

        return as_class


class LoadAddressSpace(plugin.Command):
    """Load address spaces into the session if its not already loaded."""

    __name = "load_as"

    def __init__(self, pas_spec="auto", **kwargs):
        """Tries to create the address spaces and assigns them to the session.

        An address space specification is a column delimited list of AS
        constructors which will be stacked. For example:

        FileAddressSpace:EWF

        if the specification is "auto" we guess by trying every combintion until
        a virtual AS is obtained.

        The virtual address space is chosen based on the profile.

        Args:
          pas_spec: A Physical address space specification.
        """
        super(LoadAddressSpace, self).__init__(**kwargs)
        self.pas_spec = pas_spec

    def ResolveAddressSpace(self, name):
        """Resolve the name into an address space.

        This function is intended to be called from plugins which allow an
        address space to be specified on the command line. We implement a simple
        way for the user to specify the address space using a string. The
        following formats are supported:

        Kernel, K : Represents the kernel address space.
        Physical, P: Represents the physical address space.

        as_type@dtb_address: Instantiates the address space at the specified
            DTB. For example: amd64@0x18700
        """
        # We can already specify a proper address space here.
        if isinstance(name, addrspace.BaseAddressSpace):
            return name

        if name == "K" or name == "Kernel":
            return (self.session.kernel_address_space or
                    self.GetVirtualAddressSpace())

        if name == "P" or name == "Physical":
            return (self.session.physical_address_space or
                    self.GetPhysicalAddressSpace())

        return self.session.default_address_space

    def GetPhysicalAddressSpace(self):
        try:
            # Try to get a physical address space.
            if self.pas_spec == "auto":
                self.session.physical_address_space = self.GuessAddressSpace()
            else:
                self.session.physical_address_space = self.AddressSpaceFactory(
                    specification=self.pas_spec)


            return self.session.physical_address_space

        except addrspace.ASAssertionError, e:
            logging.error("Could not create address space: %s" % e)

        return self.session.physical_address_space

    def GetVirtualAddressSpace(self, dtb=None):
        if dtb is None:
            dtb = self.session.GetParameter("dtb")

        if not self.session.physical_address_space:
            self.GetPhysicalAddressSpace()

        if not self.session.physical_address_space:
            raise plugin.PluginError("Unable to find physical address space.")

        self.profile = self.session.profile
        if self.profile is None:
            raise plugin.PluginError(
                "Must specify a profile to load virtual AS.")

        # If we know the DTB, just build the address space.
        # Otherwise, delegate to a find_dtb plugin.
        find_dtb = self.session.plugins.find_dtb()

        if dtb:
            self.session.kernel_address_space = find_dtb.CreateAS(dtb)

        else:
            logging.debug("DTB not specified. Delegating to find_dtb.")
            for address_space in find_dtb.address_space_hits():
                self.session.kernel_address_space = address_space
                self.session.SetParameter("dtb", address_space.dtb)
                break

            if self.session.kernel_address_space is None:
                logging.info(
                    "A DTB value was found but failed to verify. "
                    "Some troubleshooting steps to consider: "
                    "(1) Is the profile correct? (2) Is the KASLR correct? "
                    "Try running the find_kaslr plugin on systems that "
                    "use KASLR and see if there are more possible values. "
                    "You can specify which offset to use using "
                    "--vm_kernel_slide. (3) If you know the DTB, for "
                    "example from knowing the value of the CR3 register "
                    "at time of acquisition, you can set it using --dtb. "
                    "On most 64-bit systems, you can use the DTB of any "
                    "process, not just the kernel!")
                raise plugin.PluginError(
                    "A DTB value was found but failed to verify. "
                    "See logging messages for more information.")

        if self.session.default_address_space is None:
            self.session.default_address_space = \
                self.session.kernel_address_space

        return self.session.kernel_address_space

    def GuessAddressSpace(self, base_as=None, **kwargs):
        """Loads an address space by stacking valid ASes on top of each other
        (priority order first).
        """
        base_as = base_as
        error = addrspace.AddrSpaceError()

        address_spaces = sorted(addrspace.BaseAddressSpace.classes.values(),
                                key=lambda x: x.order)

        while 1:
            logging.debug("Voting round")
            found = False
            for cls in address_spaces:
                # Only try address spaces which claim to support images.
                if not cls.metadata("image"):
                    continue

                logging.debug("Trying %s ", cls)
                try:
                    base_as = cls(base=base_as, session=self.session,
                                  **kwargs)
                    logging.debug("Succeeded instantiating %s", base_as)
                    found = True
                    break
                except (AssertionError, addrspace.ASAssertionError), e:
                    logging.debug("Failed instantiating %s: %s",
                                  cls.__name__, e)
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

        if base_as:
            logging.info("Autodetected physical address space %s", base_as)
        else:
            logging.error("Failed to autodetect image file format. "
                          "Try running plugins.load_as with the pas_spec "
                          "parameter.")

        return base_as

    def AddressSpaceFactory(self, specification='', **kwargs):
        """Build the address space from the specification.

        Args:
           specification: A column separated list of AS class names to be
           stacked.
        """
        base_as = None
        for as_name in specification.split(":"):
            as_cls = addrspace.BaseAddressSpace.classes.get(as_name)
            if as_cls is None:
                raise addrspace.Error("No such address space %s" % as_name)

            base_as = as_cls(base=base_as, session=self.session, **kwargs)

        return base_as

    def render(self, renderer):
        if not self.session.physical_address_space:
            self.GetPhysicalAddressSpace()

        if not self.session.kernel_address_space:
            self.GetVirtualAddressSpace()


class OutputFileMixin(object):
    """A mixin for plugins that want to dump a single user controlled output."""
    @classmethod
    def args(cls, parser):
        """Declare the command line args we need."""
        super(OutputFileMixin, cls).args(parser)
        parser.add_argument("out_file",
                            help="Path for output file.")

    def __init__(self, out_file=None, **kwargs):
        super(OutputFileMixin, self).__init__(**kwargs)
        if out_file is None:
            raise RuntimeError("An output must be provided.")

        self.output = open(out_file, mode="w")


class DirectoryDumperMixin(object):
    """A mixin for plugins that want to dump files to a directory."""

    # Set this to True if the dump_dir parameter should be optional.
    dump_dir_optional = False

    @classmethod
    def args(cls, parser):
        """Declare the command line args we need."""
        super(DirectoryDumperMixin, cls).args(parser)
        help = "Path suitable for dumping files."
        if cls.dump_dir_optional:
            help += " (Optional)"
        else:
            help += " (Required)"

        parser.add_argument("-D", "--dump-dir",
                            required=not cls.dump_dir_optional,
                            help=help)

    def __init__(self, dump_dir=None, **kwargs):
        """Dump to a directory.

        Args:
          dump_dir: The directory where files should be dumped.
        """
        super(DirectoryDumperMixin, self).__init__(**kwargs)

        self.dump_dir = dump_dir or self.session.dump_dir
        self.check_dump_dir(self.dump_dir)

    def check_dump_dir(self, dump_dir=None):
        # If the dump_dir parameter is not optional insist its there.
        if not self.dump_dir_optional and not dump_dir:
            raise plugin.PluginError(
                "Please specify a dump directory.")

        if dump_dir and not os.path.isdir(dump_dir):
            raise plugin.PluginError("%s is not a directory" % self.dump_dir)

    def CopyToFile(self, address_space, start, end, outfd):
        """Copy a part of the address space to the output file.

        This utility function allows the writing of sparse files correctly. We
        pass over the address space, automatically skipping regions which are
        not valid. For file systems which support sparse files (e.g. in Linux),
        no additional disk space will be used for unmapped regions.

        If a region has no mapped pages, the resulting file will be of 0 bytes
        long.
        """
        BUFFSIZE = 1024 * 1024

        for offset, _, length in address_space.get_address_ranges(start, end):
            outfd.seek(offset - start)
            i = offset

            # Now copy the region in fixed size buffers.
            while i < offset + length:
                to_read = min(BUFFSIZE, length)

                data = address_space.read(i, to_read)
                outfd.write(data)

                i += to_read


class Null(plugin.Command):
    """This plugin does absolutely nothing.

    It is used to measure startup overheads.
    """
    __name = "null"

    def render(self, renderer):
        _ = renderer


class LoadPlugins(plugin.Command):
    """Load user provided plugins.

    This probably is only useful after the interactive shell started since you
    can already use the --plugin command line option.
    """

    __name = "load_plugin"
    interactive = True

    def __init__(self, path, **kwargs):
        super(LoadPlugins, self).__init__(**kwargs)
        if isinstance(path, basestring):
            path = [path]

        args.LoadPlugins(path)


class Printer(plugin.Command):
    """A plugin to print an object."""

    __name = "p"
    interactive = True

    def __init__(self, target=None, **kwargs):
        """Prints an object to the screen."""
        super(Printer, self).__init__(**kwargs)
        self.target = target

    def render(self, renderer):
        for line in utils.SmartStr(self.target).splitlines():
            renderer.write(line + "\n")


class Lister(Printer):
    """A plugin to list objects."""

    __name = "l"
    interactive = True

    def render(self, renderer):
        if self.target is None:
            logging.error("You must list something.")
            return

        for item in self.target:
            self.session.plugins.p(target=item).render(renderer)


class DT(plugin.ProfileCommand):
    """Print a symbol.

    Really just a convenience function for instantiating the object over the
    dummy address space.
    """

    __name = "dt"

    @classmethod
    def args(cls, parser):
        super(DT, cls).args(parser)
        parser.add_argument("target",
                            help="Name of a struct definition.")

    def __init__(self, target=None, profile=None, **kwargs):
        """Prints an object to the screen."""
        super(DT, self).__init__(**kwargs)
        self.profile = profile or self.session.profile
        self.target = target
        if target is None:
            raise plugin.PluginError("You must specify something to print.")

        if not isinstance(target, str):
            raise plugin.PluginError("Target must be a string.")

    def render(self, renderer):
        item = self.profile.Object(self.target)
        self.session.plugins.p(item).render(renderer)


class Dump(plugin.Command):
    """Hexdump an object or memory location."""

    __name = "dump"

    @classmethod
    def args(cls, parser):
        super(Dump, cls).args(parser)
        parser.add_argument("offset", action=config.IntParser,
                            help="An offset to hexdump.")

    def __init__(self, target=None, offset=0, width=16, rows=30,
                 suppress_headers=False, **kwargs):
        # pylint: disable=C0301
        """Hexdump an object or memory location.

        You can use this plugin repeateadely to keep dumping more data using the
        "p _" (print last result) operation:

        In [2]: dump session.kernel_address_space, 0x814b13b0
        ------> dump(session.kernel_address_space, 0x814b13b0)
        Offset                         Hex                              Data
        ---------- ------------------------------------------------ ----------------
        0x814b13b0 03 00 1b 00 00 00 00 00 b8 13 4b 81 b8 13 4b 81  ..........K...K.

        Out[3]: <rekall.plugins.core.Dump at 0x2967510>

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
        # pylint: enable=C0301
        super(Dump, self).__init__(**kwargs)
        if isinstance(target, (int, long)):
            offset = target
            target = None
        elif isinstance(target, basestring):
            offset = self.session.address_resolver.get_address_by_name(target)
            target = None

        if target is None:
            self.session.plugins.load_as(session=self.session).render(None)
            target = self.session.kernel_address_space


        self.target = target
        self.offset = int(offset)
        self.width = int(width)
        self.rows = int(rows)
        self.suppress_headers = suppress_headers

    def render(self, renderer):
        # Its an object
        if isinstance(self.target, obj.BaseObject):
            data = self.target.obj_vm.read(self.target.obj_offset,
                                           self.target.size())
        # Its an address space
        elif isinstance(self.target, addrspace.BaseAddressSpace):
            data = self.target.read(self.offset, self.width * self.rows)

        # If the target is an integer we assume it means an offset to read from
        # the default_address_space.
        elif isinstance(self.target, (int, long)):
            if self.offset == 0:
                self.offset = self.target

            data = self.session.default_address_space.read(
                self.offset, self.width * self.rows)

        # Its a string or something else:
        else:
            data = utils.SmartStr(self.target)

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


class Grep(plugin.Command):
    """Search an address space for keywords."""

    __name = "grep"

    @classmethod
    def args(cls, parser):
        super(Grep, cls).args(parser)
        parser.add_argument("--address_space", default="Kernel",
                            help="Name of the address_space to search.")

        parser.add_argument("--offset", default=0, action=config.IntParser,
                            help="Start searching from this offset.")

        parser.add_argument("keyword",
                            help="The binary string to find.")

        parser.add_argument("--limit", default=1024*1024,
                            help="The length of data to search.")

    def __init__(self, address_space=None, offset=0, keyword=None, context=20,
                 limit=1024 * 1024, **kwargs):
        """Search an address space for keywords.

        Args:
          address_space: Name of the address_space to search.
          offset: Start searching from this offset.
          keyword: The binary string to find.
          limit: The length of data to search.
        """
        super(Grep, self).__init__(**kwargs)
        self.keyword = keyword
        self.context = context
        self.offset = offset
        self.limit = limit
        load_as = self.session.plugins.load_as(session=self.session)
        self.address_space = load_as.ResolveAddressSpace(address_space)

    def _GenerateHits(self, data):
        start = 0
        while 1:
            idx = data.find(self.keyword, start)
            if idx == -1:
                break

            yield idx
            start = idx + 1

    def render(self, renderer):
        renderer.table_header([("Offset", "offset", "[addr]"),
                               ("Hex", "hex", "^" + str(3 * self.context)),
                               ("Data", "data", "^" + str(self.context)),
                               ("Comment", "comment", "")]
                              )

        offset = self.offset
        while offset < self.offset + self.limit:
            data = self.address_space.read(offset, 4096)
            for idx in self._GenerateHits(data):
                for _, hexdata, translated_data in utils.Hexdump(
                    data[idx-20:idx+20], width=self.context):
                    comment = ""
                    symbol, _ = self.session.address_resolver.get_nearest_constant_by_address(offset + idx)
                    if symbol:
                        comment = "%s+0x%X" % (symbol[0].obj_name,
                                               offset + idx - int(symbol[0]))

                    renderer.table_row(
                        offset + idx - 20, hexdata, "".join(translated_data),
                        comment)

            offset += len(data)

        self.offset = offset



class MemmapMixIn(object):
    """A Mixin used to create the memmap plugins for all the operating systems."""

    @classmethod
    def args(cls, parser):
        """Declare the command line args we need."""
        super(MemmapMixIn, cls).args(parser)
        parser.add_argument(
            "--coalesce", default=False, action="store_true",
            help="Merge contiguous pages into larger ranges.")

    def __init__(self, coalesce=False, **kwargs):
        """Calculates the memory regions mapped by a process.

        Args:
          coalesce: Merge pages which are contiguous in memory into larger
             ranges.
        """
        self.coalesce = coalesce
        super(MemmapMixIn, self).__init__(**kwargs)

    def render(self, renderer):
        for task in self.filter_processes():
            renderer.section()
            renderer.RenderProgress("Dumping pid {0}".format(task.pid))

            task_space = task.get_process_address_space()
            renderer.format(u"Process: '{0}' pid: {1:6}\n",
                            task.name, task.pid)

            if not task_space:
                renderer.write("Unable to read pages for task.\n")
                continue

            renderer.table_header([("Virtual", "offset_v", "[addrpad]"),
                                   ("Physical", "offset_p", "[addrpad]"),
                                   ("Size", "process_size", "[addr]")])

            if self.coalesce:
                ranges = task_space.get_address_ranges()
            else:
                ranges = task_space.get_available_addresses()

            for virtual_address, phys_address, length in ranges:
                renderer.table_row(virtual_address, phys_address, length)
