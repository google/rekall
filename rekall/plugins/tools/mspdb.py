# Rekall Memory Forensics
# Copyright 2014 Google Inc. All Rights Reserved.
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

# pylint: disable=protected-access

"""These plugins are for manipulating Microsoft PDB file.

References:
https://code.google.com/p/pdbparse/
http://moyix.blogspot.de/2007/10/types-stream.html
http://undocumented.rawol.com/win_pdbx.zip

Our goal here is not to be a complete parser for PDB files. Rather, we are
trying to extract only the important information we need in order to build a
Rekall profile. This means that we dont necessarily care about modifiers like
"const" "volatile" etc, but mostly care about struct, enums, bitfields etc.

If you are comparing the code here with the code in the pdbparse project, be
aware that due to the crazy way the construct library (which is used by
pdbparse) splits up bits, the ordering in the pdbparse code does not follow the
correct bit number (bits are defined in the order they appear in the bit stream,
which for a little endian number is non intuitive). e.g.

CV_property = BitStruct("prop",
    Flag("fwdref"),
    Flag("opcast"),
    Flag("opassign"),
    Flag("cnested"),
    Flag("isnested"),
    Flag("ovlops"),
    Flag("ctor"),
    Flag("packed"),

    BitField("reserved", 7, swapped=True),
    Flag("scoped"),
)

Actually is this struct (i.e. above the first field is bit 7, then 6 etc until
bit 0 the bit 15 down to 8):

typedef struct _CV_prop_t
        {
/*000.0*/ WORD packed   : 1;
/*000.1*/ WORD ctor     : 1;
/*000.2*/ WORD ovlops   : 1;
/*000.3*/ WORD isnested : 1;
/*000.4*/ WORD cnested  : 1;
/*000.5*/ WORD opassign : 1;
/*000.6*/ WORD opcast   : 1;
/*000.7*/ WORD fwdref   : 1;
/*001.0*/ WORD scoped   : 1;
/*001.1*/ WORD reserved : 7;
/*002*/ }
        CV_prop_t, *PCV_prop_t, **PPCV_prop_t;

Since we are lazy and do not want to hand code all the structure definitions, we
simply build a profile from the C implementation, and then use it here directly
using the "mspdb" profile (which is available in the profile repository).

http://undocumented.rawol.com/win_pdbx.zip: ./sbs_sdk/include/pdb_info.h
"""

__author__ = "Michael Cohen <scudette@gmail.com>"

import logging
import ntpath
import os
import subprocess
import urllib2

from rekall import addrspace
from rekall import plugin
from rekall import obj
from rekall import testlib
from rekall import utils

from rekall.plugins import core
from rekall.plugins.addrspaces import standard
from rekall.plugins.overlays import basic
from rekall.plugins.overlays.windows import pe_vtypes


class FetchPDB(core.DirectoryDumperMixin, plugin.Command):
    """Fetch the PDB file for an executable from the Microsoft PDB server."""

    __name = "fetch_pdb"

    SYM_URLS = ['http://msdl.microsoft.com/download/symbols']
    USER_AGENT = "Microsoft-Symbol-Server/6.6.0007.5"

    @classmethod
    def args(cls, parser):
        parser.add_argument(
            "--filename", default=None,
            help="The filename of the executable to get the PDB file for.")

        super(FetchPDB, cls).args(parser)

    def __init__(self, filename=None, **kwargs):
        super(FetchPDB, self).__init__(**kwargs)
        self.pe = pe_vtypes.PE(filename=filename)

    def render(self, renderer):
        data_directory = self.pe.nt_header.OptionalHeader.DataDirectory[
            "IMAGE_DIRECTORY_ENTRY_DEBUG"].VirtualAddress.dereference_as(
            "_IMAGE_DEBUG_DIRECTORY")

        # We only support the more recent RSDS format.
        debug = data_directory.AddressOfRawData.dereference_as("CV_RSDS_HEADER")

        if debug.Signature != "RSDS":
            logging.error("PDB stream %s not supported.", debug.Signature)
            return

        filename = ntpath.basename(str(debug.Filename))
        guid = ("%s%x" % (debug.GUID.AsString, debug.Age)).upper()

        for url in self.SYM_URLS:
            try:
                basename = ntpath.splitext(filename)[0]
                url += "/%s/%s/%s.pd_" % (filename, guid, basename)

                renderer.format("Trying to fetch {0}\n", url)
                request = urllib2.Request(url, None, headers={
                        'User-Agent': self.USER_AGENT})

                data = urllib2.urlopen(request).read()
                renderer.format("Received {0} bytes\n", len(data))

                output_file = os.path.join(self.dump_dir, "%s.pd_" % basename)
                with open(output_file, "wb") as fd:
                    fd.write(data)

                try:
                    subprocess.check_call(["cabextract", output_file],
                                          cwd=self.dump_dir)
                except subprocess.CalledProcessError:
                    renderer.format(
                        "Failed to decompress output file {0}. "
                        "Ensure cabextract is installed.\n", output_file)

                break

            except IOError as e:
                logging.error(e)
                continue


class TestFetchPDB(testlib.DisabledTest):
    """Disable this test."""
    PARAMETERS = dict(commandline="fetch_pdb")


def Pages(length, page_size):
    """Calculate the number of pages required to store a stream."""
    num_pages = length / page_size
    if length % page_size:
        num_pages += 1

    return num_pages


class StreamBasedAddressSpace(addrspace.CachingAddressSpaceMixIn,
                              addrspace.RunBasedAddressSpace):
    """An address space which combines together the page lists.

    Once we parse the page list, we can build this address space which takes
    care of reassembling the stream for us automatically.
    """

    def __init__(self, pages=None, page_size=None, **kwargs):
        super(StreamBasedAddressSpace, self).__init__(**kwargs)
        self.pages = pages
        self.PAGE_SIZE = page_size = int(page_size)
        for i, page in enumerate(pages):
            self.runs.append((i * page_size, page * page_size, page_size))

####################################################################
# The following parses the TPI stream (stream 2).
####################################################################

# Inside TPI stream we have a list of records. The type of the struct stored in
# the record is declared by use of the _LEAF_ENUM_e enum. The following lookup
# map is used to map from the _LEAF_ENUM_e to the BaseObject class to
# instantiate.
LEAF_ENUM_TO_TYPE = dict(
    LF_STRUCTURE="_lfClass",
    LF_ARRAY="_lfArray",
    LF_PROCEDURE="_lfProc",
    LF_POINTER="_lfPointer",
    LF_ARGLIST="_lfArgList",
    LF_MODIFIER="_lfModifier",
    LF_FIELDLIST="_lfFieldList",
    LF_ENUM="_lfEnum",
    LF_UNION="_lfUnion",
    LF_BITFIELD="_lfBitfield",

    LF_CHAR="byte",
    LF_SHORT="short int",
    LF_USHORT="unsigned short int",
    LF_LONG="long",
    LF_ULONG="unsigned long",
    )

# The SubRecord field is a union which depends on the _LEAF_ENUM_e. The
# following maps these to the enum fields. There are other members in the union,
# but we dont care about them.
LEAF_ENUM_TO_SUBRECORD = dict(
    LF_MEMBER="Member",
    LF_ENUMERATE="Enumerate",
    )


mspdb_overlays = {
    # The file header. We only support newer versions.
    "_PDB_HEADER_700": [None, {
            "abSignature": [None, ["Signature", dict(
                        value="Microsoft C/C++ MSF 7.00\r\n\x1ADS\0\0\0"
                        )]],

            # Total number of pages in the root stream.
            "root_pages": lambda x: Pages(x.dRootBytes, x.dPageBytes),

            # This is an array of page indexes which make up the page list of
            # the root stream.
            "adIndexPages": [None, ["Array", dict(
                        target="unsigned int",
                        # The root page list is stored in the index stream. Each
                        # page index is 4 bytes.
                        count=lambda x: Pages(4 * x.root_pages, x.dPageBytes),
                        )]],
            }],

    # The header of the root stream (This applies once we reconstruct the root
    # stream). It defines the page indexes of all the streams in this file.
    "_PDB_ROOT_700": [lambda x: (x.dStreams + 1) * 4, {
            "adStreamBytes": [None, ["Array", dict(
                        count=lambda x: x.dStreams,
                        target="unsigned int",
                        )]],
            }],

    # A modifier adds some flags to its modified_type.
    "_lfModifier": [None, {
            "modified_type": [2, ["unsigned int"]],
            "modifier": [6, ["Flags", dict(
                        bitmap=dict(
                            unaligned=2,
                            volatile=1,
                            const=0
                            ),
                        target="unsigned short int",
                        )]],
            }],

    # The size of the SubRecord itself is the size of the value. (ie. depends on
    # the _LEAF_ENUM_e). We must calculate the exact size because SubRecords (of
    # variable size) are stored back to back in the lfFieldList.
    "_lfSubRecord": [lambda x: x.value.size(), {
            "leaf": [None, ["Enumeration", dict(
                        enum_name="_LEAF_ENUM_e",
                        target="unsigned short int")]],

            # This psuedo value automatically selects the correct member of the
            # union based on the leaf value.
            "value": lambda x: x.m(
                LEAF_ENUM_TO_SUBRECORD.get(str(x.leaf), ""))
            }],

    "_lfEnum": [None, {
            # The name of the enum element.
            "Name": [None, ["String"]],
            }],

    # A lfFieldList holds a back to back variable length array of SubRecords.
    "_lfFieldList": [None, {
            "SubRecord": [None, ["ListArray", dict(
                        target="_lfSubRecord",

                        # Total length is determined by the size of the
                        # container.
                        maximum_size=lambda x: x.obj_parent.length - 2
                        )]],
            }],

    # Arg list for a function.
    "_lfArgList": [None, {
            # This is a list of _TYPE_ENUM_e, or an index reference into the TPI
            # stream.
            "arg": [None, ["Array", dict(
                        target="Enumeration",
                        target_args=dict(
                            enum_name="_TYPE_ENUM_e",
                            target="unsigned short int",
                            ),
                        count=lambda x: x.count
                        )]],
            }],

    # A helper type to select the correct implementation.
    "TypeContainer": [lambda x: x.length+2, {
            "length": [0, ["unsigned short int"]],

            # Depending on the value of this enum, this field must be cast to
            # the correct struct.
            "type_enum": [2, ["Enumeration", dict(
                        enum_name="_LEAF_ENUM_e",
                        target="unsigned short int"
                        )]],

            # Depending on the enumeration above, the type_enum field must be
            # cast into one of these structs.
            "type": lambda x: x.type_enum.cast(
                LEAF_ENUM_TO_TYPE.get(str(x.type_enum), "unsigned int"))
            }],

    # This is the TPI stream header. It is followed by a list of TypeContainers
    # for all the types in this stream.
    "_HDR": [None, {
            "types": [lambda x: x.size(),
                      ["ListArray", dict(
                        target="TypeContainer",
                        count=lambda x: x.tiMac - x.tiMin,
                        maximum_size=lambda x: x.cbGprec,
                        )]],
            }],
    }


class lfClass(obj.Struct):
    """Represents a class or struct."""

    def __init__(self, **kwargs):
        super(lfClass, self).__init__(**kwargs)
        self._DecodeVariableData()

    def size(self):
        """Our size is the end of the object plus any padding."""
        return pe_vtypes.RoundUp(self.obj_end - self.obj_offset)

    def _DecodeVariableData(self):
        """This object is followed by a variable sized data structure.

        This data structure contains the "value_" and "name" attributes. If the
        first short int less than 0x8000, it represents the value. Otherwise, it
        represents an _LEAF_ENUM_e enum which determines the size of the value
        to read next (e.g. LF_ULONG = 4 bytes, LF_SHORT = 2 bytes) and those
        represent the value.

        The name field then follows as a String.

        Following the name field, there is padding to 4 byte alignment.

        We must calculate the total size of this struct in this function, after
        parsing all the components.
        """

        obj_end = self.obj_offset + super(lfClass, self).size()
        field_type = self.obj_profile.Object(
            "unsigned short int", offset=obj_end, vm=self.obj_vm)

        obj_end += field_type.size()

        if field_type < 0x8000:
            self.value_ = field_type
            self.name = self.obj_profile.String(
                offset=obj_end, vm=self.obj_vm)

            obj_end += self.name.size()

        else:
            # The field type is an LF_ENUM which determines which struct this
            # is.
            type_enum_name = self.obj_profile.get_constant(
                "_LEAF_ENUM_e").get(str(field_type))

            type_name = LEAF_ENUM_TO_TYPE.get(type_enum_name)

            self.value_ = self.obj_profile.Object(
                type_name=type_name, offset=obj_end, vm=self.obj_vm)

            # The name follows the value.
            self.name = self.obj_profile.String(
                offset=self.value_.obj_offset + self.value_.size(),
                vm=self.obj_vm)

            obj_end += self.value_.size() + self.name.size()

        # Record the end of the object
        self.obj_end = obj_end

        if self.name == "<unnamed-tag>":
            # Generate a unique name for this object.
            self.name = "__unnamed_%X" % self.obj_offset

    def Definition(self, _):
        """Returns the vtype data structure defining this element.

        Returns:
          a tuple, the first element is the target name, the second is the dict
          of the target_args.
        """
        # The target is just the name of this class.
        return str(self.name), {}


class lfEnumerate(lfClass):
    """A SubRecord describing a single enumeration definition."""


class lfBitfield(obj.Struct):
    """A range of bits."""

    def Definition(self, tpi):
        """BitField overlays on top of another type."""
        target, target_args = tpi.DefinitionByIndex(self.type)

        return "BitField", dict(
            start_bit=int(self.position),
            end_bit=int(self.position) + int(self.length),
            target_args=target_args, target=target)


class lfUnion(lfClass):
    """A Union is basically the same as a struct, except members may overlap."""


class lfModifier(lfClass):
    def Definition(self, tpi):
        """We dont really care about modifiers, just pass the utype through."""
        return tpi.DefinitionByIndex(self.modified_type)


class lfEnum(obj.Struct):
    """Represents an enumeration definition."""

    def Definition(self, tpi):
        """Enumerations are defined in two parts.

        First an enumeration dict is added to the profile constants, and then
        the target "Enumeration" can use it by name (having the enum_name
        field). This allows many fields which use the same enumeration to share
        the definition dict.
        """
        enumeration = {}
        for x in tpi.Resolve(self.field).SubRecord:
            enumeration[int(x.value.value_)] = str(x.value.name)

        enum_name = str(self.Name)
        if enum_name == "<unnamed-tag>":
            enum_name = "ENUM_%X" % self.obj_offset

        tpi.AddEnumeration(enum_name, enumeration)

        target, target_args = tpi.DefinitionByIndex(self.utype)

        return "Enumeration", dict(
            target=target, target_args=target_args, enum_name=enum_name)

class lfPointer(lfClass):
    """A Pointer object."""

    def Definition(self, tpi):
        target_index = int(self.u1.utype)
        target, target_args = tpi.DefinitionByIndex(target_index)

        return ["Pointer", dict(
                target=target,
                target_args=target_args)]


class lfProc(lfClass):
    """A Function object."""

    def Definition(self, tpi):
        """We record the function arg prototype as well."""
        args = []
        for idx in tpi.Resolve(self.arglist).arg:
            definition = tpi.DefinitionByIndex(idx)
            if definition:
                args.append(definition)

        return "Function", dict(args=args)



class lfArray(lfClass):
    """An array of the same object."""

    def Definition(self, tpi):
        target, target_args = tpi.DefinitionByIndex(self.elemtype)
        return ["Array", dict(
                target=target, target_args=target_args,
                count=int(self.value_),
                )]

class lfMember(lfClass):
    """A member in a struct (or class)."""

    def Definition(self, tpi):
        """Returns a tuple of target, target_args for the member."""
        return tpi.DefinitionByIndex(self.m("index"))


class _PDB_HEADER_700(obj.Struct):
    """The file header of a PDB file."""

    def get_page_list(self):
        """The full page list is a double indexed array."""
        result = []
        for idx in self.adIndexPages:
            for page_number in self.obj_profile.Array(
                offset=idx*self.dPageBytes, vm=self.obj_vm,
                target="unsigned int", count=self.dPageBytes/4):
                result.append(int(page_number))
                if len(result) >= self.root_pages:
                    return result

        return result


class _PDB_ROOT_700(obj.Struct):
    """The root stream contains information about all other streams."""

    def _GetStreams(self):
        """Read all the streams in the file."""
        offset_of_index_list = self.obj_offset + self.size()
        page_size = self.obj_context["page_size"]

        for stream_size in self.adStreamBytes:
            if stream_size == 0xffffffff:
                stream_size = 0

            page_list = self.obj_profile.Array(
                offset=offset_of_index_list, vm=self.obj_vm,
                count=Pages(stream_size, page_size),
                target="unsigned int")

            offset_of_index_list += page_list.size()

            yield StreamBasedAddressSpace(
                base=self.obj_vm.base, page_size=page_size,
                pages=page_list)

    SUPPORTED_STREAMS = {
        2: "_HDR",
#        1: "InfoStream",
#        3: "DebugStream"
        }

    def GetStream(self, number):
        """Only return the required streams, discarding the rest."""
        for i, address_space in enumerate(self._GetStreams()):
            if i == number:
                return self.obj_profile.Object(
                    self.SUPPORTED_STREAMS[i], vm=address_space)


class PDBProfile(basic.Profile32Bits, basic.BasicClasses):
    """A profile to parse Microsoft PDB files.

    Note that this is built on top of the mspdb profile which exists in the
    profile repository, as generated from the code here:

    http://undocumented.rawol.com/win_pdbx.zip

    Do not directly instantiate this. Just do:

    profile = session.LoadProfile("mspdb")
    """

    def __init__(self, **kwargs):
        super(PDBProfile, self).__init__(**kwargs)
        self.add_overlay(mspdb_overlays)
        self.add_classes({
                "_PDB_HEADER_700": _PDB_HEADER_700,
                "_PDB_ROOT_700": _PDB_ROOT_700,
                "_lfClass": lfClass, "_lfArray": lfArray,
                "_lfMember": lfMember, "_lfPointer": lfPointer,
                "_lfProc": lfProc, "_lfEnum": lfEnum,
                "_lfModifier": lfModifier, "_lfUnion": lfUnion,
                "_lfBitfield": lfBitfield, "_lfEnumerate": lfEnumerate,
                })


class TPI(object):
    """Abstracts away the TPI stream semantics."""

    # A mapping between _TYPE_ENUM_e basic pdb types and vtype
    # descriptions. Keys: The _TYPE_ENUM_e enum, values a tuple of target,
    # target_args for instantiating the Rekall object describing this type.
    TYPE_ENUM_TO_VTYPE = {
        "T_32PINT4": ["Pointer", dict(target="long")],
        "T_32PLONG": ["Pointer", dict(target="long")],
        "T_32PQUAD": ["Pointer", dict(target="long long")],
        "T_32PRCHAR": ["Pointer", dict(target="unsigned char")],
        "T_32PREAL32": ["Pointer", dict(target="Void")],
        "T_32PREAL64": ["Pointer", dict(target="Void")],
        "T_32PSHORT": ["Pointer", dict(target="short")],
        "T_32PUCHAR": ["Pointer", dict(target="unsigned char")],
        "T_32PUINT4": ["Pointer", dict(target="unsigned int")],
        "T_32PULONG": ["Pointer", dict(target="unsigned long")],
        "T_32PUQUAD": ["Pointer", dict(target="unsigned long long")],
        "T_32PUSHORT": ["Pointer", dict(target="unsigned short")],
        "T_32PVOID": ["Pointer", dict(target="Void")],
        "T_32PWCHAR": ["Pointer", dict(target="UnicodeString")],
        "T_64PLONG": ["Pointer", dict(target="long")],
        "T_64PQUAD": ["Pointer", dict(target="long long")],
        "T_64PRCHAR": ["Pointer", dict(target="unsigned char")],
        "T_64PUCHAR": ["Pointer", dict(target="unsigned char")],
        "T_64PULONG": ["Pointer", dict(target="unsigned long")],
        "T_64PUQUAD": ["Pointer", dict(target="unsigned long long")],
        "T_64PUSHORT": ["Pointer", dict(target="unsigned short")],
        "T_64PVOID": ["Pointer", dict(target="Void")],
        "T_BOOL08": ["unsigned char", {}],
        "T_CHAR": ["char", {}],
        "T_INT4": ["long", {}],
        "T_INT8": ["long long", {}],
        "T_LONG": ["long", {}],
        "T_QUAD": ["long long", {}],
        "T_RCHAR": ["unsigned char", {}],
        "T_REAL32": ["float", {}],
        "T_REAL64": ["double", {}],
        "T_REAL80": ["long double", {}],
        "T_SHORT": ["short", {}],
        "T_UCHAR": ["unsigned char", {}],
        "T_UINT4": ["unsigned long", {}],
        "T_ULONG": ["unsigned long", {}],
        "T_UQUAD": ["unsigned long long", {}],
        "T_USHORT": ["unsigned short", {}],
        "T_VOID": ["Void", {}],
        "T_WCHAR": ["UnicodeString", {}],
    }

    def __init__(self, filename, session):
        self.session = session
        self.enums = {}
        self.profile = self.session.LoadProfile("mspdb")
        self._TYPE_ENUM_e = self.profile.get_constant("_TYPE_ENUM_e")
        self._TYPE_ENUM_e = dict(
            (int(x), y) for x, y in self._TYPE_ENUM_e.items())

        self.address_space = standard.FileAddressSpace(filename=filename)
        self.header = self.profile._PDB_HEADER_700(
            vm=self.address_space, offset=0)

        if not self.header.abSignature.is_valid():
            raise IOError("PDB file not supported.")

        root_pages = self.header.get_page_list()

        root_stream = StreamBasedAddressSpace(
            base=self.address_space, page_size=self.header.dPageBytes,
            pages=root_pages)

        root_stream_header = self.profile._PDB_ROOT_700(
            offset=0,
            vm=root_stream,
            context=dict(
                page_size=self.header.dPageBytes
                )
            )

        self.lookup = {}
        tpi = root_stream_header.GetStream(2)
        for i, t in enumerate(tpi.types):
            self.session.report_progress()

            self.lookup[tpi.tiMin + i] = t
            if not t:
                break

    def AddEnumeration(self, name, enumeration):
        self.enums[name] = enumeration

    def Structs(self):
        for v in self.lookup.itervalues():
            # Ignore the forward references.
            if (v.type_enum == "LF_STRUCTURE" or
                v.type_enum == "LF_UNION") and not v.type.property.fwdref:
                struct_name = v.type.name
                struct_size = int(v.type.value_)

                field_list = self.lookup[int(v.type.field)].type
                definition = [struct_size, {}]

                for field in field_list.SubRecord:
                    field_definition = field.value.Definition(self)
                    if field_definition:
                        definition[1][str(field.value.name)] = [
                            int(field.value.value_), field_definition]

                yield struct_name, definition

    def DefinitionByIndex(self, idx):
        """Return the vtype definition of the item identified by idx."""
        if idx < 0x700:
            type_name = self._TYPE_ENUM_e.get(idx)
            return self.TYPE_ENUM_TO_VTYPE.get(type_name)

        try:
            return self.lookup[idx].type.Definition(self)
        except AttributeError:
            return "Void", {}

    def Resolve(self, idx):
        try:
            return self.lookup[idx].type
        except KeyError:
            return obj.NoneObject("Index not known")


class ParsePDB(plugin.Command):
    """Parse the PDB streams."""

    __name = "parse_pdb"

    @classmethod
    def args(cls, parser):
        super(ParsePDB, cls).args(parser)

        parser.add_argument(
            "-f", "--filename", default=None,
            help="The filename of the PDB file.")

        parser.add_argument(
            "--profile_class", default="BaseWindowsProfile",
            help="The name of the profile implementation. ")

    def __init__(self, filename=None, profile_class=None, **kwargs):
        super(ParsePDB, self).__init__(**kwargs)
        self.tpi = TPI(filename, self.session)
        self.profile_class = profile_class

    def render(self, renderer):
        vtypes = {}

        for i, (struct_name, definition) in enumerate(self.tpi.Structs()):
            self.session.report_progress(" %s: %s", i, struct_name)
            vtypes[str(struct_name)] = definition

        result = {
            "$METADATA": dict(
                Type="Profile",

                # This should probably be changed for something more specific.
                ProfileClass=self.profile_class),
            "$STRUCTS": vtypes,
            }


        renderer.write(utils.PPrint(result))
