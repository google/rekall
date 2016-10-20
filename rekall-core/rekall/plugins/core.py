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

import exceptions
import inspect
import pdb
import math
import re
import os
import textwrap

from rekall import addrspace
from rekall import args
from rekall import config
from rekall import constants
from rekall import registry
from rekall import plugin
from rekall import obj
from rekall import scan
from rekall import testlib
from rekall import utils


class Info(plugin.Command):
    """Print information about various subsystems."""

    __name = "info"

    standard_options = []

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

        metadata = config.CommandMetadata(item)
        for x, y in metadata.args.items():
            # Normalize the option name to use _.
            x = x.replace("-", "_")

            yield x, self._clean_up_doc(y.get("help", ""))

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
                "http://www.rekall-forensic.com/epydocs/%s.%s-class.html"
                "\n\n" % (item.__module__, item.__name__))

            renderer.write(doc_string)

            renderer.table_header([('Parameter', 'parameter', '30'),
                                   ('Documentation', 'doc', '70')])
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

    def render_general_info(self, renderer):
        renderer.write(constants.BANNER)
        renderer.section()
        renderer.table_header([('Command', 'function', "20"),
                               ('Provider Class', 'provider', '20'),
                               ('Docs', 'docs', '50')])

        for cls, name, doc in sorted(self.plugins(), key=lambda x: x[1]):
            renderer.table_row(name, cls, doc)


class TestInfo(testlib.DisabledTest):
    """Disable the Info test."""

    PARAMETERS = dict(commandline="info")


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
          BaseAddressSpace-derived instances, validated using the VerifyHit()
          method.
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

    def GetAddressSpaceImplementation(self, simple=False):
        """Returns the correct address space class for this profile."""
        # The virtual address space implementation is chosen by the profile.
        architecture = self.profile.metadata("arch")
        if architecture == "AMD64":
            impl = "AMD64PagedMemory"

        # PAE profiles go with the pae address space.
        elif architecture == "I386" and self.profile.metadata("pae"):
            impl = 'IA32PagedMemoryPae'

        elif architecture == "MIPS":
            impl = "MIPS32PagedMemory"

        else:
            impl = 'IA32PagedMemory'

        as_class = addrspace.BaseAddressSpace.classes[impl]
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

    # Parse Address spaces from this specification. TODO: Support EPT
    # specification and nesting.
    ADDRESS_SPACE_RE = re.compile("([a-zA-Z0-9]+)@((0x)?[0-9a-zA-Z]+)")

    def ResolveAddressSpace(self, name=None):
        """Resolve the name into an address space.

        This function is intended to be called from plugins which allow an
        address space to be specified on the command line. We implement a simple
        way for the user to specify the address space using a string. The
        following formats are supported:

        Kernel, K : Represents the kernel address space.
        Physical, P: Represents the physical address space.

        as_type@dtb_address: Instantiates the address space at the specified
            DTB. For example: amd64@0x18700

        pid@pid_number: Use the process address space for the specified pid.
        """
        if name is None:
            result = self.session.GetParameter("default_address_space")
            if result:
                return result

            name = "K"

        # We can already specify a proper address space here.
        if isinstance(name, addrspace.BaseAddressSpace):
            return name

        if name == "K" or name == "Kernel":
            return (self.session.kernel_address_space or
                    self.GetVirtualAddressSpace())

        if name == "P" or name == "Physical":
            return (self.session.physical_address_space or
                    self.GetPhysicalAddressSpace())

        m = self.ADDRESS_SPACE_RE.match(name)
        if m:
            arg = int(m.group(2), 0)
            if m.group(1) == "pid":
                for task in self.session.plugins.pslist(
                        pid=arg).filter_processes():
                    return task.get_process_address_space()
                raise AttributeError("Process pid %s not found" % arg)

            as_cls = addrspace.BaseAddressSpace.classes.get(m.group(1))
            if as_cls:
                return as_cls(session=self.session, dtb=arg,
                              base=self.GetPhysicalAddressSpace())

        raise AttributeError("Address space specification %r invalid.", name)

    def GetPhysicalAddressSpace(self):
        try:
            # Try to get a physical address space.
            if self.pas_spec == "auto":
                self.session.physical_address_space = self.GuessAddressSpace()
            else:
                self.session.physical_address_space = self.AddressSpaceFactory(
                    specification=self.pas_spec)

            return self.session.physical_address_space

        except addrspace.ASAssertionError as e:
            self.session.logging.error("Could not create address space: %s" % e)

        return self.session.physical_address_space

    # TODO: Deprecate this method completely since it is rarely used.
    def GetVirtualAddressSpace(self, dtb=None):
        """Load the Kernel Virtual Address Space.

        Note that this function is usually not used since the Virtual AS is now
        loaded from guess_profile.ApplyFindDTB() when profiles are guessed. This
        function is only used when the profile is directly provided by the user.
        """
        if not self.session.physical_address_space:
            self.GetPhysicalAddressSpace()

        if not self.session.physical_address_space:
            raise plugin.PluginError("Unable to find physical address space.")

        self.profile = self.session.profile
        if self.profile == None:
            raise plugin.PluginError(
                "Must specify a profile to load virtual AS.")

        # If we know the DTB, just build the address space.
        # Otherwise, delegate to a find_dtb plugin.
        if dtb is None:
            dtb = self.session.GetParameter("dtb")

        find_dtb = self.session.plugins.find_dtb()
        if find_dtb == None:
            return find_dtb

        if dtb:
            self.session.kernel_address_space = find_dtb.CreateAS(dtb)

        else:
            self.session.logging.debug("DTB not specified. Delegating to "
                                       "find_dtb.")
            for address_space in find_dtb.address_space_hits():
                with self.session:
                    self.session.kernel_address_space = address_space
                    self.session.SetCache("dtb", address_space.dtb,
                                          volatile=False)
                    break

            if self.session.kernel_address_space is None:
                self.session.logging.info(
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

        # Set the default address space for plugins like disassemble and dump.
        if not self.session.HasParameter("default_address_space"):
            self.session.SetCache(
                "default_address_space", self.session.kernel_address_space,
                volatile=False)

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
            self.session.logging.debug("Voting round with base: %s", base_as)
            found = False
            for cls in address_spaces:
                # Only try address spaces which claim to support images.
                if not cls.metadata("image"):
                    continue

                self.session.logging.debug("Trying %s ", cls)
                try:
                    base_as = cls(base=base_as, session=self.session,
                                  **kwargs)
                    self.session.logging.debug("Succeeded instantiating %s",
                                               base_as)
                    found = True
                    break
                except (AssertionError,
                        addrspace.ASAssertionError) as e:
                    self.session.logging.debug("Failed instantiating %s: %s",
                                               cls.__name__, e)
                    error.append_reason(cls.__name__, e)
                    continue
                except Exception as e:
                    self.session.logging.info("Error: %s", e)
                    if self.session.GetParameter("debug"):
                        pdb.post_mortem()

                    raise

            # A full iteration through all the classes without anyone
            # selecting us means we are done:
            if not found:
                break

        if base_as:
            self.session.logging.info("Autodetected physical address space %s",
                                      base_as)

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


class DirectoryDumperMixin(object):
    """A mixin for plugins that want to dump files to a directory."""

    # Set this to False if the dump_dir parameter is mandatory.
    dump_dir_optional = True
    default_dump_dir = "."

    __args = [
        dict(name="dump_dir",
             help="Path suitable for dumping files.")
    ]

    def __init__(self, *args_, **kwargs):
        """Dump to a directory.

        Args:
          dump_dir: The directory where files should be dumped.
        """
        super(DirectoryDumperMixin, self).__init__(*args_, **kwargs)
        self.dump_dir = (self.plugin_args.dump_dir or
                         self.default_dump_dir or
                         self.session.GetParameter("dump_dir"))

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

        for run in address_space.get_address_ranges(start=start, end=end):
            out_offset = run.start - start
            self.session.report_progress("Dumping %s Mb", out_offset / BUFFSIZE)
            outfd.seek(out_offset)
            i = run.start

            # Now copy the region in fixed size buffers.
            while i < run.end:
                to_read = min(BUFFSIZE, run.end - i)

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
            renderer.format("{0}\n", line)


class Lister(Printer):
    """A plugin to list objects."""

    __name = "l"
    interactive = True

    def render(self, renderer):
        if self.target is None:
            self.session.logging.error("You must list something.")
            return

        for item in self.target:
            self.session.plugins.p(target=item).render(renderer)


class DT(plugin.TypedProfileCommand, plugin.ProfileCommand):
    """Print a struct or other symbol.

    Really just a convenience function for instantiating the object and printing
    all its members.
    """

    __name = "dt"

    __args = [
        dict(name="target", positional=True, required=True,
             help="Name of a struct definition."),

        dict(name="offset", type="IntParser", default=0,
             required=False, help="Name of a struct definition."),

        dict(name="address_space", type="AddressSpace",
             help="The address space to use."),

        dict(name="member_offset", type="IntParser",
             help="If specified we only show the member at this "
             "offset.")
    ]

    def render_Struct(self, renderer, struct):
        renderer.format(
            "[{0} {1}] @ {2:addrpad} \n",
            struct.obj_type, struct.obj_name or '',
            self.plugin_args.offset or struct.obj_offset)

        end_address = struct.obj_size + struct.obj_offset
        width = int(math.ceil(math.log(end_address + 1, 16)))
        renderer.table_header([
            dict(name="Offset", type="TreeNode", max_depth=5,
                 child=dict(style="address", width=width+5),
                 align="l"),
            ("Field", "field", "30"),
            dict(name="content", style="typed")])

        self._render_Struct(renderer, struct)

    def _render_Struct(self, renderer, struct, depth=0):
        fields = []
        # Print all the fields sorted by offset within the struct.
        for k in set(struct.members).union(struct.callable_members):
            member = getattr(struct, k)
            base_member = struct.m(k)

            offset = base_member.obj_offset
            if offset == None:  # NoneObjects screw up sorting order here.
                offset = -1

            fields.append((offset, k, member))

        for offset, k, v in sorted(fields):
            if self.plugin_args.member_offset is not None:
                if offset == self.plugin_args.member_offset:
                    renderer.table_row(offset, k, v, depth=depth)
            else:
                renderer.table_row(offset, k, v, depth=depth)

            if isinstance(v, obj.Struct):
                self._render_Struct(renderer, v, depth=depth + 1)

    def render(self, renderer):
        if isinstance(self.plugin_args.target, basestring):
            self.plugin_args.target = self.profile.Object(
                type_name=self.plugin_args.target,
                offset=self.plugin_args.offset,
                vm=self.plugin_args.address_space)

        item = self.plugin_args.target

        if isinstance(item, obj.Pointer):
            item = item.deref()

        if isinstance(item, obj.Struct):
            return self.render_Struct(renderer, item)

        self.session.plugins.p(self.plugin_args.target).render(renderer)


class AddressMap(object):
    """Label memory ranges."""
    _COLORS = u"BLACK RED GREEN YELLOW BLUE MAGENTA CYAN WHITE".split()

    # All color combinations except those with the same foreground an background
    # colors, since these will be invisible.
    COLORS = []
    UNREADABLE = [
        ("CYAN", "GREEN"),
        ("GREEN", "CYAN"),
        ("MAGENTA", "YELLOW"),
        ("YELLOW", "MAGENTA"),

    ]
    for x in _COLORS:
        for y in _COLORS:
            if x != y and (x, y) not in UNREADABLE:
                COLORS.append((x, y))

    def __init__(self):
        self.collection = utils.RangedCollection()
        self.idx = 0
        self.label_color_map = {}

    def AddRange(self, start, end, label, color_index=None):
        try:
            fg, bg = self.label_color_map[label]
        except KeyError:
            if color_index is None:
                color_index = self.idx
                self.idx += 1

            fg, bg = self.COLORS[color_index % len(self.COLORS)]
            self.label_color_map[label] = (fg, bg)

        self.collection.insert(start, end, (label, fg, bg))

    def HighlightRange(self, start, end, relative=True):
        """Returns a highlighting list from start address to end.

        If relative is True the highlighting list is relative to the start
        offset.
        """
        result = []
        for i in range(start, end):
            _, _, hit = self.collection.get_containing_range(i)
            if hit:
                _, fg, bg = hit
                if relative:
                    i -= start

                result.append([i, i + 1, fg, bg])

        return result

    def GetComment(self, start, end):
        """Returns a tuple of labels and their highlights."""
        labels = []
        for i in range(start, end):
            start, end, hit = self.collection.get_containing_range(i)
            if hit:
                if hit not in labels:
                    labels.append(hit)

        result = ""
        highlights = []
        for label, fg, bg in labels:
            highlights.append((len(result), len(result) + len(label), fg, bg))
            result += label + ", "

        # Drop the last ,
        if result:
            result = result[:-2]

        return utils.AttributedString(result, highlights=highlights)


class Dump(plugin.TypedProfileCommand, plugin.Command):
    """Hexdump an object or memory location.

    You can use this plugin repeateadely to keep dumping more data using the
     "p _" (print last result) operation:

    In [2]: dump 0x814b13b0, address_space="K"
    ------> dump(0x814b13b0, address_space="K")
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
    """

    __name = "dump"

    __args = [
        dict(name="offset", type="SymbolAddress", positional=True,
             default=0, help="An offset to hexdump."),

        dict(name="address_space", type="AddressSpace", positional=True,
             required=False, help="The address space to use."),

        dict(name="data",
             help="Dump this string instead."),

        dict(name="length", type="IntParser",
             help="Maximum length to dump."),

        dict(name="width", type="IntParser",
             help="Number of bytes per row"),

        dict(name="rows", type="IntParser",
             help="Number of bytes per row"),
    ]

    table_header = [
        dict(name="offset", style="address"),
        dict(name="hexdump", width=65),
        dict(name="comment", width=40)
    ]

    def column_types(self):
        return dict(offset=int,
                    hexdump=utils.HexDumpedString(""),
                    comment=utils.AttributedString(""))

    def __init__(self, *args, **kwargs):
        address_map = kwargs.pop("address_map", None)
        super(Dump, self).__init__(*args, **kwargs)
        self.offset = self.plugin_args.offset

        # default width can be set in the session.
        self.width = (self.plugin_args.width or
                      self.session.GetParameter("hexdump_width", 16))


        self.rows = (self.plugin_args.rows or
                     self.session.GetParameter("paging_limit", 30))

        self.address_map = address_map or AddressMap()

        if self.plugin_args.data:
            self.plugin_args.address_space = addrspace.BufferAddressSpace(
                data=self.plugin_args.data, session=self.session)

            if self.plugin_args.length is None:
                self.plugin_args.length = len(self.plugin_args.data)

    def collect(self):
        to_read = min(
            self.width * self.rows,
            self.plugin_args.address_space.end() - self.plugin_args.offset)

        if self.plugin_args.length is not None:
            to_read = min(to_read, self.plugin_args.length)

        resolver = self.session.address_resolver
        for offset in range(self.offset, self.offset + to_read):
            comment = resolver.format_address(offset, max_distance=0)
            if comment:
                self.address_map.AddRange(offset, offset + 1, ",".join(comment))

        offset = self.offset
        for offset in range(self.offset, self.offset + to_read,
                            self.width):
            # Add a symbol name for the start of each row.
            hex_data = utils.HexDumpedString(
                self.plugin_args.address_space.read(offset, self.width),
                highlights=self.address_map.HighlightRange(
                    offset, offset + self.width, relative=True))

            comment = self.address_map.GetComment(offset, offset + self.width)

            yield dict(offset=offset,
                       hexdump=hex_data,
                       comment=comment,
                       nowrap=True, hex_width=self.width)

        # Advance the offset so we can continue from this offset next time we
        # get called.
        self.offset = offset


class Grep(plugin.TypedProfileCommand, plugin.ProfileCommand):
    """Search an address space for keywords."""

    __name = "grep"

    PROFILE_REQUIRED = False

    __args = [
        dict(name="keyword", type="ArrayString", positional=True,
             help="The binary strings to find."),

        dict(name="offset", default=0, type="IntParser",
             help="Start searching from this offset."),

        dict(name="address_space", type="AddressSpace",
             help="Name of the address_space to search."),

        dict(name="context", default=20, type="IntParser",
             help="Context to print around the hit."),

        dict(name="limit", default=2**64,
             help="The length of data to search."),
    ]

    def render(self, renderer):
        scanner = scan.MultiStringScanner(
            needles=self.plugin_args.keyword,
            address_space=self.plugin_args.address_space,
            session=self.session)

        for hit, _ in scanner.scan(offset=self.plugin_args.offset,
                                   maxlen=self.plugin_args.limit):
            hexdumper = self.session.plugins.dump(
                offset=hit - 16, length=self.plugin_args.context + 16,
                address_space=self.plugin_args.address_space)

            hexdumper.render(renderer)


class SetProcessContextMixin(object):
    """Set the current process context.

    The basic functionality of all platforms' cc plugin.
    """

    name = "cc"
    interactive = True
    process_context = None

    def __enter__(self):
        """Use this plugin as a context manager.

        When used as a context manager we save the state of the address resolver
        and then restore it on exit. This prevents the address resolver from
        losing its current state and makes switching contexts much faster.
        """
        self.process_context = self.session.GetParameter("process_context")
        return self

    def __exit__(self, unused_type, unused_value, unused_traceback):
        # Restore the process context.
        self.SwitchProcessContext(self.process_context)

    def SwitchProcessContext(self, process=None):
        if process == None:
            message = "Switching to Kernel context"
            self.session.SetCache("default_address_space",
                                  self.session.kernel_address_space,
                                  volatile=False)

        else:
            message = ("Switching to process context: {0} "
                       "(Pid {1}@{2:#x})").format(
                           process.name, process.pid, process)

            self.session.SetCache(
                "default_address_space",
                process.get_process_address_space() or None,
                volatile=False)

        # Reset the address resolver for the new context.
        self.session.SetCache("process_context", process, volatile=False)
        self.session.logging.debug(message)

        return message

    def SwitchContext(self):
        if not self.filtering_requested:
            return self.SwitchProcessContext(process=None)

        for process in self.filter_processes():
            return self.SwitchProcessContext(process=process)

        return "Process not found!\n"

    def render(self, renderer):
        message = self.SwitchContext()
        renderer.format(message + "\n")


def MethodWithAddressSpace(process=None):
    """A decorator to do an operation in another address space."""
    def wrap(f):
        def wrapped_f(self, *_args, **_kwargs):
            with self.session.plugins.cc() as cc:
                cc.SwitchProcessContext(process=process)

                return f(self, *_args, **_kwargs)
        return wrapped_f

    return wrap


class VtoPMixin(object):
    """Prints information about the virtual to physical translation."""

    name = "vtop"

    PAGE_SIZE = 0x1000

    @classmethod
    def args(cls, parser):
        super(VtoPMixin, cls).args(parser)
        parser.add_argument("virtual_address", type="SymbolAddress",
                            required=True,
                            help="The Virtual Address to examine.")

    def __init__(self, virtual_address=(), **kwargs):
        """Prints information about the virtual to physical translation.

        This is similar to windbg's !vtop extension.

        Args:
          virtual_address: The virtual address to describe.
          address_space: The address space to use (default the
            kernel_address_space).
        """
        super(VtoPMixin, self).__init__(**kwargs)
        if not isinstance(virtual_address, (tuple, list)):
            virtual_address = [virtual_address]

        self.addresses = [self.session.address_resolver.get_address_by_name(x)
                          for x in virtual_address]

    def render(self, renderer):
        if self.filtering_requested:
            with self.session.plugins.cc() as cc:
                for task in self.filter_processes():
                    cc.SwitchProcessContext(task)

                    for vaddr in self.addresses:
                        self.render_address(renderer, vaddr)

        else:
            # Use current process context.
            for vaddr in self.addresses:
                self.render_address(renderer, vaddr)

    def render_address(self, renderer, vaddr):
        renderer.section(name="{0:#08x}".format(vaddr))
        self.address_space = self.session.GetParameter("default_address_space")

        renderer.format("Virtual {0:addrpad} Page Directory {1:addr}\n",
                        vaddr, self.address_space.dtb)

        # Render each step in the translation process.
        for translation_descriptor in self.address_space.describe_vtop(vaddr):
            translation_descriptor.render(renderer)

        # The below re-does all the analysis using the address space. It should
        # agree!
        renderer.format("\nDeriving physical address from runtime "
                        "physical address space:\n")

        physical_address = self.address_space.vtop(vaddr)
        if physical_address is None:
            renderer.format("Physical Address Unavailable.\n")
        else:
            renderer.format(
                "Physical Address {0}\n",
                self.physical_address_space.describe(physical_address))


class RaisingTheRoof(plugin.Command):
    """A plugin that exists to break your tests and make you cry."""

    # Can't call this raise, because it aliases the keyword.
    name = "raise_the_roof"

    @classmethod
    def args(cls, parser):
        super(RaisingTheRoof, cls).args(parser)
        parser.add_argument("--exception_class", required=False,
                            help="The exception class to raise.")
        parser.add_argument("--exception_text", required=False,
                            help="The text to initialize the exception with.")

    def __init__(self, exception_class=None, exception_text=None, **kwargs):
        super(RaisingTheRoof, self).__init__(**kwargs)
        self.exception_class = exception_class or "ValueError"
        self.exception_text = exception_text or "Default exception"

    def render(self, renderer):
        exc_cls = getattr(exceptions, self.exception_class, ValueError)
        raise exc_cls(self.exception_text)


class TestRaisingTheRoof(testlib.DisabledTest):
    PLUGIN = "raise_the_roof"
