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

Other known implementations of PDB parsing:
https://chromium.googlesource.com/syzygy/+/master/pdb

The closest thing to official documentation can be found here:
http://pierrelib.pagesperso-orange.fr/exec_formats/MS_Symbol_Type_v1.0.pdf

"""

__author__ = "Michael Cohen <scudette@gmail.com>"

import glob
import re
import ntpath
import os
import platform
import subprocess
import sys
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


class FetchPDB(core.DirectoryDumperMixin, plugin.TypedProfileCommand,
               plugin.Command):
    """Fetch the PDB file for an executable from the Microsoft PDB server."""

    __name = "fetch_pdb"

    SYM_URLS = ['http://msdl.microsoft.com/download/symbols']
    USER_AGENT = "Microsoft-Symbol-Server/10.0.0.0"

    __args = [
        dict(name="pdb_filename", required=True, positional=True,
             help="The filename of the executable to get the PDB file for."),

        dict(name="guid", positional=True,
             help="The GUID of the pdb file. If provided, the pdb filename must"
             " be provided in the --pdb_filename parameter.")
    ]

    def render(self, renderer):
        # The filename is an executable
        if self.plugin_args.guid is None and self.plugin_args.pdb_filename:
            self.pe = pe_vtypes.PE(filename=self.plugin_args.pdb_filename,
                                   session=self.session)
            data_directory = self.pe.nt_header.OptionalHeader.DataDirectory[
                "IMAGE_DIRECTORY_ENTRY_DEBUG"].VirtualAddress.dereference_as(
                    "_IMAGE_DEBUG_DIRECTORY")

            # We only support the more recent RSDS format.
            debug = data_directory.AddressOfRawData.dereference_as(
                "CV_RSDS_HEADER")

            if debug.Signature != "RSDS":
                self.session.logging.error("PDB stream %s not supported.",
                                           debug.Signature)
                return

            self.plugin_args.pdb_filename = ntpath.basename(str(debug.Filename))
            self.plugin_args.guid = self.pe.RSDS.GUID_AGE

        elif self.plugin_args.pdb_filename is None:
            raise RuntimeError(
                "Filename must be provided when GUID is specified.")

        # Write the file data to the renderer.
        pdb_file_data = self.FetchPDBFile()
        with renderer.open(filename=self.plugin_args.pdb_filename,
                           directory=self.plugin_args.dump_dir,
                           mode="wb") as fd:
            fd.write(pdb_file_data)

    def FetchPDBFile(self):
        # Ensure the pdb filename has the correct extension.
        pdb_filename = self.plugin_args.pdb_filename
        guid = self.plugin_args.guid

        if not pdb_filename.endswith(".pdb"):
            pdb_filename += ".pdb"

        for url in self.SYM_URLS:
            basename = ntpath.splitext(pdb_filename)[0]
            url += "/%s/%s/%s.pd_" % (pdb_filename, guid, basename)

            self.session.report_progress("Trying to fetch %s\n", url)
            request = urllib2.Request(url, None, headers={
                'User-Agent': self.USER_AGENT})

            url_handler = urllib2.urlopen(request)
            with utils.TempDirectory() as temp_dir:
                compressed_output_file = os.path.join(
                    temp_dir, "%s.pd_" % basename)

                output_file = os.path.join(
                    temp_dir, "%s.pdb" % basename)

                # Download the compressed file to a temp file.
                with open(compressed_output_file, "wb") as outfd:
                    while True:
                        data = url_handler.read(8192)
                        if not data:
                            break

                        outfd.write(data)
                        self.session.report_progress(
                            "%s: Downloaded %s bytes", basename, outfd.tell())

                # Now try to decompress it with system tools. This might fail.
                try:
                    if platform.system() == "Windows":
                        # This should already be installed on windows systems.
                        subprocess.check_call(
                            ["expand", compressed_output_file, output_file],
                            cwd=temp_dir)
                    else:
                        # In Linux we just hope the cabextract program was
                        # installed.
                        subprocess.check_call(
                            ["cabextract", compressed_output_file],
                            cwd=temp_dir,
                            stdout=sys.stderr)

                except (subprocess.CalledProcessError, OSError):
                    raise RuntimeError(
                        "Failed to decompress output file %s. "
                        "Ensure cabextract is installed.\n" % output_file)

                # Sometimes the CAB file contains a PDB file with a different
                # name or casing than we expect. We use glob to find any PDB
                # files in the temp directory.
                output_file = glob.glob("%s/*pdb" % temp_dir)[0]

                # We read the entire file into memory here - it should not be
                # larger than approximately 10mb.
                with open(output_file, "rb") as fd:
                    return fd.read(50 * 1024 * 1024)


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
        i = 0
        for i, page in enumerate(pages):
            self.add_run(i * page_size, page * page_size, page_size)

        # Record the total size of the file.
        self.size = (i + 1) * page_size


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
    LF_NESTTYPE="_lfNestType",
    LF_CHAR="byte",
    LF_SHORT="short int",
    LF_USHORT="unsigned short int",
    LF_LONG="long",
    LF_ULONG="unsigned long",
    LF_64PWCHAR="Pointer",
)

# The SubRecord field is a union which depends on the _LEAF_ENUM_e. The
# following maps these to the enum fields. There are other members in the union,
# but we dont care about them.
LEAF_ENUM_TO_SUBRECORD = dict(
    LF_MEMBER="Member",
    LF_ENUMERATE="Enumerate",
    LF_NESTTYPE="NestType",
)

# A map between the symbol type enum and the actual record type.
SYM_ENUM_TO_SYM = dict(
    S_PUB32="_PUBSYM32",
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
    "_lfSubRecord": [lambda x: x.value.obj_size, {
        "leaf": [None, ["Enumeration", dict(
            enum_name="_LEAF_ENUM_e",
            target="unsigned short int")]],

        # This psuedo value automatically selects the correct member of the
        # union based on the leaf value.
        "value": lambda x: x.m(
            LEAF_ENUM_TO_SUBRECORD.get(str(x.leaf), "Unknown")),
    }],

    "_lfEnum": [None, {
        # The name of the enum element.
        "Name": [None, ["String"]],
    }],

    "_lfNestType": [None, {
        # The name of the enum element.
        "Name": [None, ["String"]],
    }],

    # A lfFieldList holds a back to back variable length array of SubRecords.
    "_lfFieldList": [None, {
        "SubRecord": [None, ["ListArray", dict(
            target="_lfSubRecord",

            # Total length is determined by the size of the
            # container.
            maximum_size=lambda x: x.obj_parent.length - 2,
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
    "TypeContainer": [lambda x: x.length + 2, {
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
        "types": [lambda x: x.obj_size,
                  ["ListArray", dict(
                      target="TypeContainer",
                      count=lambda x: x.tiMac - x.tiMin,
                      maximum_size=lambda x: x.cbGprec,
                  )]],
    }],

    "_GUID": [16, {
        "Data1": [0, ["unsigned long", {}]],
        "Data2": [4, ["unsigned short", {}]],
        "Data3": [6, ["unsigned short", {}]],
        "Data4": [8, ["String", dict(length=8, term=None)]],
        "AsString": lambda x: ("%08x%04x%04x%s" % (
            x.Data1, x.Data2, x.Data3, str(x.Data4).encode('hex'))).upper(),
    }],

    "Info": [None, {
        "Version": [0, ["unsigned long int"]],
        "TimeDateStamp": [4, ["UnixTimeStamp"]],
        "Age": [8, ["unsigned long int"]],
        "GUID": [12, ["_GUID"]],
    }],

    # The record length does not include the tag.
    "_ALIGNSYM": [lambda x: x.reclen + 2, {
        "rectyp": [None, ["Enumeration", dict(
            enum_name="_SYM_ENUM_e",
            target="unsigned short int")]],

        # The real record type depends on the _SYM_ENUM_e.
        "value": lambda x: x.cast(
            SYM_ENUM_TO_SYM.get(str(x.rectyp), ""))

    }],

    "_PUBSYM32": [None, {
        "name": [None, ["String"]],
    }],

    "DBI": [None, {
        "DBIHdr": [0, ["_NewDBIHdr"]],
        "ExHeaders": [64, ["ListArray", dict(
            maximum_size=lambda x: x.DBIHdr.cbGpModi,
            target="DBIExHeaders")]],
    }],

    "DBIExHeaders": [None, {
        "modName": [64, ["String"]],
        "objName": [lambda x: x.modName.obj_offset + x.modName.obj_size,
                    ["String"]],
    }],

    "IMAGE_SECTION_HEADER": [None, {
        "Name": [None, ["String"]],
    }],

}


class lfClass(obj.Struct):
    """Represents a class or struct."""

    _obj_end = 0

    def __init__(self, **kwargs):
        super(lfClass, self).__init__(**kwargs)
        self._DecodeVariableData()

    @utils.safe_property
    def obj_size(self):
        """Our size is the end of the object plus any padding."""
        return pe_vtypes.RoundUpToWordAlignment(
            self.obj_end - self.obj_offset)

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

        obj_end = self.obj_offset + super(lfClass, self).obj_size
        field_type = self.obj_profile.Object(
            "unsigned short int", offset=obj_end, vm=self.obj_vm)

        obj_end += field_type.obj_size

        if field_type < 0x8000:
            self.value_ = field_type
            self.name = self.obj_profile.String(
                offset=obj_end, vm=self.obj_vm)

            obj_end += self.name.obj_size

        else:
            # The field type is an LF_ENUM which determines which struct this
            # is.
            type_enum_name = self.obj_profile.get_enum(
                "_LEAF_ENUM_e").get(str(field_type))

            type_name = LEAF_ENUM_TO_TYPE.get(type_enum_name)

            self.value_ = self.obj_profile.Object(
                type_name=type_name, offset=obj_end, vm=self.obj_vm)

            # The name follows the value.
            self.name = self.obj_profile.String(
                offset=self.value_.obj_offset + self.value_.obj_size,
                vm=self.obj_vm)

            obj_end += self.value_.obj_size + self.name.obj_size

        # Record the end of the object
        self._obj_end = obj_end

        # Sometimes the field is named '__unnamed' so we disambiguate it here.
        if self.name == "__unnamed":
            self.name = "__unnamed_%s" % self.field

    @utils.safe_property
    def obj_end(self):
        return self._obj_end

    def Definition(self, _):
        """Returns the vtype data structure defining this element.

        Returns:
          a tuple, the first element is the target name, the second is the dict
          of the target_args.
        """
        # The target is just the name of this class.
        return [str(self.name), {}]


class lfEnumerate(lfClass):
    """A SubRecord describing a single enumeration definition."""


class lfBitfield(obj.Struct):
    """A range of bits."""

    def Definition(self, tpi):
        """BitField overlays on top of another type."""
        result = tpi.DefinitionByIndex(self.type)
        if not result:
            return [str(self.name), {}]

        target, target_args = result

        return "BitField", dict(
            start_bit=int(self.position),
            end_bit=int(self.position) + int(self.length),
            target_args=target_args, target=target)


class lfNestType(obj.Struct):
    UNNAMED_RE = re.compile("<unnamed-type-([^->]+)>")

    def __init__(self, **kwargs):
        super(lfNestType, self).__init__(**kwargs)
        self.value_ = 0
        self.name = str(self.Name)
        m = self.UNNAMED_RE.match(self.name)
        if m:
            self.name = m.group(1)

    @utils.safe_property
    def obj_size(self):
        """Our size is the end of the object plus any padding."""
        return pe_vtypes.RoundUpToWordAlignment(
            self.Name.obj_offset + self.Name.obj_size)

    def Definition(self, tpi):
        return tpi.DefinitionByIndex(self.index)


class lfUnion(lfClass):
    """A Union is basically the same as a struct, except members may overlap."""


class lfModifier(lfClass):
    def Definition(self, tpi):
        """We dont really care about modifiers, just pass the utype through."""
        return tpi.DefinitionByIndex(self.modified_type)


class lfEnum(obj.Struct):
    """Represents an enumeration definition."""

    @utils.safe_property
    def Name(self):
        enum_name = str(self.m("Name"))
        if enum_name == "<unnamed-tag>":
            enum_name = "ENUM_%X" % self.obj_offset

        return enum_name

    def AddEnumeration(self, tpi):
        enumeration = {}
        reverse_enumeration = {}
        for x in tpi.Resolve(self.field).SubRecord:
            enumeration[int(x.value.value_)] = str(x.value.name)
            reverse_enumeration[str(x.value.name)] = int(x.value.value_)

        tpi.AddEnumeration(self.Name, enumeration)
        tpi.AddReverseEnumeration(self.Name, reverse_enumeration)

    def Definition(self, tpi):
        """Enumerations are defined in two parts.

        First an enumeration dict is added to the profile constants, and then
        the target "Enumeration" can use it by name (having the enum_name
        field). This allows many fields which use the same enumeration to share
        the definition dict.
        """
        result = tpi.DefinitionByIndex(self.utype)
        if not result:
            return [str(self.name), {}]

        target, target_args = result

        return "Enumeration", dict(
            target=target, target_args=target_args, enum_name=self.Name)


class lfPointer(lfClass):
    """A Pointer object."""

    def Definition(self, tpi):
        target_index = int(self.u1.utype)
        result = tpi.DefinitionByIndex(target_index)
        if not result:
            return [str(self.name), {}]

        target, target_args = result

        return ["Pointer", dict(
            target=target,
            target_args=target_args
        )]


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
        result = tpi.DefinitionByIndex(self.elemtype)
        if not result:
            return [str(self.name), {}]

        target, target_args = result
        if target == "<unnamed-tag>":
            target = "<unnamed-%s>" % self.elemtype

        # Note that we only specify the total size of the array. We have no idea
        # how many items fit at this stage because we dont know the exact size
        # of the elements. The post processing step will convert the size into a
        # count.
        definition = ["Array", dict(
            target=target, target_args=target_args,
            size=int(self.value_),
        )]

        tpi.RegisterFixUp(definition)

        return definition


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
                    offset=idx * self.dPageBytes, vm=self.obj_vm,
                    target="unsigned int", count=self.dPageBytes / 4):
                result.append(int(page_number))
                if len(result) >= self.root_pages:
                    return result

        return result


class _PDB_ROOT_700(obj.Struct):
    """The root stream contains information about all other streams."""

    def _GetStreams(self):
        """Read all the streams in the file."""
        offset_of_index_list = self.obj_offset + self.obj_size
        page_size = self.obj_context["page_size"]

        for stream_size in self.adStreamBytes:
            if stream_size == 0xffffffff:
                stream_size = 0

            page_list = self.obj_profile.Array(
                offset=offset_of_index_list, vm=self.obj_vm,
                count=Pages(stream_size, page_size),
                target="unsigned int")

            offset_of_index_list += page_list.obj_size

            yield StreamBasedAddressSpace(
                base=self.obj_vm.base, page_size=page_size,
                session=self.obj_profile.session, pages=page_list)

    def GetStream(self, number):
        """Only return the required streams, discarding the rest."""
        for i, address_space in enumerate(self._GetStreams()):
            if i == number:
                return address_space


class DBIExHeaders(obj.Struct):
    @utils.safe_property
    def obj_size(self):
        return (pe_vtypes.RoundUpToWordAlignment(
            self.objName.obj_offset + self.objName.obj_size) -
                self.obj_offset)


class DBI(obj.Struct):
    def DBGHeader(self):
        DBIHdr = self.DBIHdr
        # Skip over all these sections which we dont care about until we get to
        # the debug header at the end.
        header_offset = (self.obj_offset +
                         DBIHdr.obj_size +
                         DBIHdr.cbGpModi +
                         DBIHdr.cbSC +
                         DBIHdr.cbSecMap +
                         DBIHdr.cbFileInfo +
                         DBIHdr.cbTSMap +
                         DBIHdr.cbECInfo)

        return self.obj_profile.DbgHdr(header_offset, vm=self.obj_vm)


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
            "_lfNestType": lfNestType, "DBIExHeaders": DBIExHeaders,
            "DBI": DBI
        })


class PDBParser(object):
    """Parses a Microsoft PDB file."""

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
        "T_64PWCHAR": ["Pointer", dict(target="String")],
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
        self.fixups = []
        self.enums = {}
        self.rev_enums = {}
        self.constants = {}
        self.functions = {}
        self.profile = self.session.LoadProfile("mspdb")
        self._TYPE_ENUM_e = self.profile.get_enum("_TYPE_ENUM_e")
        self._TYPE_ENUM_e = dict(
            (int(x), y) for x, y in self._TYPE_ENUM_e.items())

        self.address_space = standard.FileAddressSpace(
            filename=filename, session=self.session)
        self.header = self.profile._PDB_HEADER_700(
            vm=self.address_space, offset=0)

        if not self.header.abSignature.is_valid():
            raise IOError("PDB file not supported.")

        root_pages = self.header.get_page_list()

        root_stream = StreamBasedAddressSpace(
            base=self.address_space, page_size=self.header.dPageBytes,
            pages=root_pages, session=self.profile.session)

        self.root_stream_header = self.profile._PDB_ROOT_700(
            offset=0,
            vm=root_stream,
            context=dict(
                page_size=self.header.dPageBytes
            )
        )

        self.ParsePDB()
        self.ParseDBI()
        self.ParseTPI()

    def ParsePDB(self):
        """Parse the PDB info stream."""
        # Get the info stream.
        info = self.profile.Info(vm=self.root_stream_header.GetStream(1))
        self.metadata = dict(
            Version=int(info.Version),
            Timestamp=str(info.TimeDateStamp),
            GUID_AGE="%s%X" % (info.GUID.AsString, info.Age),
        )

    def ParseDBI(self):
        """Parse the DBI stream.

        This fires off subparsers for contained streams.
        """
        dbi = self.profile.DBI(vm=self.root_stream_header.GetStream(3))
        DBGHeader = dbi.DBGHeader()

        # Sometimes this stream is set to 0xFFFF so we need to use the other
        # stream.
        section_stream = DBGHeader.snSectionHdrOrig
        if section_stream == 0xFFFF:
            section_stream = DBGHeader.snSectionHdr

        self.ParseSectionHeaders(section_stream)
        self.ParseOMAP(DBGHeader.snOmapFromSrc)
        self.ParseGlobalSymbols(dbi.DBIHdr.u1.snSymRecs)

    def ParseSectionHeaders(self, stream_id):
        """Gather the PE sections of this executable."""
        self.sections = []
        stream = self.root_stream_header.GetStream(stream_id)
        if stream is None:
            return

        for section in self.profile.ListArray(
                maximum_size=stream.size,
                target="IMAGE_SECTION_HEADER", vm=stream):
            self.sections.append(section)

    def ParseOMAP(self, omap_stream_id):
        """Build an OMAP lookup table.

        The OMAP is a translation between the original symbol's offset to the
        final offset. When the linker builds the executable, it reorders the
        original object files in the executable section. This translation table
        tells us where the symbols end up.
        """
        self.omap = utils.SortedCollection(key=lambda x: x[0])
        omap_stream = self.root_stream_header.GetStream(omap_stream_id)
        if omap_stream is None:
            return

        omap_address_space = addrspace.BufferAddressSpace(
            session=self.session,
            data=omap_stream.read(0, omap_stream.size))

        omap_array = self.profile.Array(
            vm=omap_address_space,
            count=omap_stream.size / self.profile.get_obj_size("_OMAP_DATA"),
            max_count=omap_stream.size,
            target="_OMAP_DATA")

        for i, omap in enumerate(omap_array):
            src = int(omap.rva)
            dest = int(omap.rvaTo)

            self.omap.insert((src, dest))
            self.session.report_progress(
                " Extracting OMAP Information %s%%",
                lambda: i * 100 / omap_array.count)

    def ParseGlobalSymbols(self, stream_id):
        """Parse the symbol records stream."""
        stream = self.root_stream_header.GetStream(stream_id)
        for container in self.profile.ListArray(target="_ALIGNSYM", vm=stream,
                                                maximum_size=stream.size):

            if container.reclen == 0:
                break

            symbol = container.value

            # Skip unknown records for now.
            if not symbol:
                self.session.logging.warning(
                    "Unimplemented symbol %s" % container.rectyp)
                continue

            try:
                name = str(symbol.name)
            except AttributeError:
                # We do not support symbols without name (e.g. annotations).
                continue

            translated_offset = offset = int(symbol.off)

            # Some files do not have OMAP information or section information. In
            # that case we just export the symbol offsets untranslated.
            if self.sections:
                # Convert the RVA to a virtual address by referencing into the
                # correct section.
                translated_offset = virtual_address = (
                    offset + self.sections[symbol.seg - 1].VirtualAddress)

                # If there is no OMAP specified we just translate the symbol
                # into the right section.
                if self.omap:
                    # Translate the offset according to the OMAP.
                    try:
                        from_offset, dest_offset = self.omap.find_le(
                            virtual_address)

                        translated_offset = (
                            virtual_address - from_offset + dest_offset)

                    except ValueError:
                        pass

            if symbol.pubsymflags.u1.fFunction:
                self.functions[name] = translated_offset
            else:
                self.constants[name] = translated_offset

            self.session.report_progress(" Parsing Symbols %s", name)

    def ParseTPI(self):
        """The TPI stream contains all the struct definitions."""
        self.lookup = {}
        tpi = self.profile._HDR(vm=self.root_stream_header.GetStream(2))

        # Build a lookup table for fast resolving of TPI indexes.
        for i, t in enumerate(tpi.types):
            self.session.report_progress(" Parsing Structs %(spinner)s")

            self.lookup[tpi.tiMin + i] = t
            if not t:
                break

        # Extract ALL enumerations, even if they are not referenced by any
        # structs.
        for value in self.lookup.values():
            if value.type_enum == "LF_ENUM":
                value.type.AddEnumeration(self)

    def AddEnumeration(self, name, enumeration):
        self.enums[name] = enumeration

    def AddReverseEnumeration(self, name, enumeration):
        self.rev_enums[name] = enumeration

    def RegisterFixUp(self, definition):
        self.fixups.append(definition)

    def Structs(self):
        for key, value in self.lookup.iteritems():
            # Ignore the forward references.
            if ((value.type_enum == "LF_STRUCTURE" or
                 value.type_enum == "LF_UNION") and
                    not value.type.property.fwdref):

                struct_name = value.type.name
                if struct_name == "<unnamed-tag>":
                    struct_name = "<unnamed-%s>" % key

                struct_size = int(value.type.value_)

                field_list = self.lookup[int(value.type.field)].type
                definition = [struct_size, {}]

                for field in field_list.SubRecord:
                    field_definition = field.value.Definition(self)
                    if field_definition:
                        if field_definition[0] == "<unnamed-tag>":
                            field_definition[0] = (
                                "<unnamed-%s>" % field.value.index)

                        definition[1][str(field.value.name)] = [
                            int(field.value.value_), field_definition]

                yield [struct_name, definition]

    def DefinitionByIndex(self, idx):
        """Return the vtype definition of the item identified by idx."""
        result = None
        if idx < 0x700:
            type_name = self._TYPE_ENUM_e.get(idx)

            result = self.TYPE_ENUM_TO_VTYPE.get(type_name)
            if result is None and type_name != "T_NOTYPE":
                self.session.logging.error("Unrecognized type %s\n", type_name)

        else:
            try:
                result = self.lookup[idx].type.Definition(self)
            except AttributeError:
                pass

        return result

    def Resolve(self, idx):
        try:
            return self.lookup[idx].type
        except KeyError:
            return obj.NoneObject("Index not known")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, trace):
        self.address_space.close()


class ParsePDB(core.DirectoryDumperMixin, plugin.TypedProfileCommand,
               plugin.Command):
    """Parse the PDB streams."""

    __name = "parse_pdb"

    __args = [
        dict(name="pdb_filename", required=True, positional=True,
             help="The filename of the PDB file."),

        dict(name="profile_class",
             help="The name of the profile implementation. "
             "Default name is derived from the pdb filename."),

        dict(name="output_filename",
             help="The name of the file to store this profile. "),

        dict(name="windows_version",
             help="The windows version (major.minor.revision) "
             "corresponding with this PDB. For example, Windows 7 "
             "should be given as 6.1"),

        dict(name="concise", type="Boolean",
             help="Specify this to emit less detailed information."),
    ]

    def __init__(self, *args, **kwargs):
        self.metadata = kwargs.pop("metadata", {})
        super(ParsePDB, self).__init__(*args, **kwargs)

        profile_class = self.metadata.get(
            "ProfileClass", self.plugin_args.profile_class)

        # By default select the class with the same name as the pdb file.
        if profile_class is None:
            profile_class = os.path.splitext(
                os.path.basename(self.plugin_args.pdb_filename))[0].capitalize()

            if profile_class not in obj.Profile.classes:
                profile_class = "BasicPEProfile"

        self.plugin_args.profile_class = profile_class

        versions = []
        if self.plugin_args.windows_version is not None:
            versions = self.plugin_args.windows_version.split(".", 2)

            for i, metadata in enumerate(["major", "minor", "rev"]):
                try:
                    self.metadata[metadata] = versions[i]
                except IndexError:
                    break

        self.tpi = PDBParser(self.plugin_args.pdb_filename, self.session)

    NATIVE_TYPE_SIZE = {
        "unsigned char": 1,
        "unsigned int": 4,
        "unsigned long": 4,
        "unsigned long long": 8,
        "unsigned short": 2,
        "char": 1,
        "int": 4,
        "long": 4,
        "long long": 8,
        "short": 2,
    }

    def PostProcessVTypes(self, vtypes):
        """Post process the vtypes to optimize some access members."""
        arch = self.metadata.get("arch", "AMD64")

        for defintion in self.tpi.fixups:
            target, target_args = defintion
            if target == "Array":
                # The PDB symbols specify a UnicodeString as an array of wide
                # char but we need to fix it to be a UnicodeString with a
                # specified length.
                if target_args.get("target") == "UnicodeString":
                    defintion[0] = "UnicodeString"
                    defintion[1] = dict(
                        length=target_args.get("size") / 2
                    )
                elif target_args.has_key("size"):
                    # Work out the array target size.
                    array_target = target_args.get("target")
                    target_size = self.NATIVE_TYPE_SIZE.get(array_target)
                    if target_size is None:
                        if array_target == "Pointer":
                            target_size = 8 if arch == "AMD64" else 4
                        else:
                            target_definition = vtypes.get(array_target)
                            if target_definition is None:
                                # We have no idea what size it is. Leave the
                                # size parameter for the object system to work
                                # out during runtime.
                                continue

                            target_size = target_definition[0]

                    # Replace the size with a count.
                    target_args["count"] = target_args.pop(
                        "size") / target_size

        return vtypes

    def parse_pdb(self):
        with self.tpi:
            vtypes = {}

            for i, (struct_name, definition) in enumerate(self.tpi.Structs()):
                self.session.report_progress(
                    " Exporting %s: %s", i, struct_name)

                struct_name = str(struct_name)
                existing_definition = vtypes.get(struct_name)
                if existing_definition:
                    # Merge the old definition into the new definition.
                    definition[1].update(existing_definition[1])

                vtypes[struct_name] = definition

            self.metadata.update(dict(
                ProfileClass=self.plugin_args.profile_class,
                Type="Profile",
                PDBFile=os.path.basename(self.plugin_args.pdb_filename),
            ))

            self.metadata.update(self.tpi.metadata)

            # Demangle all constants.
            demangler = pe_vtypes.Demangler(self.metadata)
            constants = {}
            for name, value in self.tpi.constants.iteritems():
                constants[demangler.DemangleName(name)] = value

            functions = {}
            for name, value in self.tpi.functions.iteritems():
                functions[demangler.DemangleName(name)] = value

            vtypes = self.PostProcessVTypes(vtypes)

            result = {
                "$METADATA": self.metadata,
                "$STRUCTS": vtypes,
                "$ENUMS": self.tpi.enums,
            }

            if not self.plugin_args.concise:
                result["$REVENUMS"] = self.tpi.rev_enums
                result["$CONSTANTS"] = constants
                result["$FUNCTIONS"] = functions

            return result

    def render(self, renderer):
        result = self.parse_pdb()

        if self.plugin_args.output_filename:
            with renderer.open(filename=self.plugin_args.output_filename,
                               directory=self.plugin_args.dump_dir,
                               mode="wb") as fd:
                fd.write(utils.PPrint(result))
        else:
            renderer.write(utils.PPrint(result))
