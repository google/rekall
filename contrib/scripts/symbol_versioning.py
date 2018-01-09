#!/bin/python

"""This script removes an ELF binaries symbol versioning.

This is needed to allow the binary to run on older systems reliably.

See the Rekall's blog post "ELF hacking with Rekall"
"""
import argparse

from rekall import session
from rekall.plugins.overlays.linux import elf
from rekall.plugins.addrspaces import standard


def fix_version_needed(hdr):
    verneed = hdr.section_by_name(".gnu.version_r").get_section()
    to_be_changed = {}
    source_verneed = {}
    acceptable_versions = ["GLIBC_2.2.5", "GLIBC_2.3", "GCC_3.0"]
    for needed in verneed:
        filename = str(needed.file)
        print (filename)
        for aux in needed.aux:
            version_name = str(aux.name)
            if version_name in acceptable_versions:
                print (version_name, " is acceptable")
            else:
                print (version_name, " is not acceptable")

            # Take a source which is old enough
            if (filename not in source_verneed and
                version_name in acceptable_versions):
                source_verneed[filename] = aux

            # Remember all the aux records which are newer than the
            # oldest source.
            if version_name not in acceptable_versions:
                to_be_changed.setdefault(filename, []).append(aux)

    # Now patch all the newer records.
    for filename, to_be_changed_list in to_be_changed.items():
        template = source_verneed[filename]
        for aux in to_be_changed_list:
            # Need to update both the hash and the name.
            aux.vna_hash = template.vna_hash
            aux.vna_name = template.vna_name


def remove_symbol_versions(hdr):
    versyms = hdr.section_by_name(".gnu.version")
    sym_table = versyms.get_section()
    # Just remove all versions from all symbols.
    for i, other_ref in enumerate(sym_table):
        sym_table[i] = 0



if __name__ == "__main__":
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument(
        'binary',
        default=None,
        help="Path to the ELF binary."
    )

    args = argument_parser.parse_args()
    print ("***Modifying file %s **" % args.binary)

    vm = standard.WritableAddressSpace(
        filename=args.binary, session=session.Session(), mode="r+b")
    profile = elf.ELFProfile(session=session)
    hdr = profile.elf64_hdr(vm=vm, offset=0)

    fix_version_needed(hdr)
    remove_symbol_versions(hdr)
