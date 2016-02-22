//
//  main.c
//  macho
//
//  Created by Adam Sindelar on 1/22/16.
//  Copyright (c) 2016 Rekall. All rights reserved.
//

#include <mach-o/loader.h>

int main() {

    struct mach_header mach_header;
    struct mach_header_64 mach_header_64;
    struct load_command load_command;
    union lc_str lc_str;
    struct segment_command segment_command;
    struct segment_command_64 segment_command_64;
    struct section section;
    struct section_64 section_64;
    struct fvmlib fvmlib;
    struct fvmlib_command fvmlib_command;
    struct dylib dylib;
    struct dylib_command dylib_command;
    struct sub_framework_command sub_framework_command;
    struct sub_client_command sub_client_command;
    struct sub_umbrella_command sub_umbrella_command;
    struct sub_library_command sub_library_command;
    struct prebound_dylib_command prebound_dylib_command;
    struct dylinker_command dylinker_command;
    struct thread_command thread_command;
    struct routines_command routines_command;
    struct routines_command_64 routines_command_64;
    struct symtab_command symtab_command;
    struct dysymtab_command dysymtab_command;
    struct dylib_table_of_contents dylib_table_of_contents;
    struct dylib_module dylib_module;
    struct dylib_module_64 dylib_module_64;
    struct dylib_reference dylib_reference;
    struct twolevel_hints_command twolevel_hints_command;
    struct twolevel_hint twolevel_hint;
    struct prebind_cksum_command prebind_cksum_command;
    struct uuid_command uuid_command;
    struct rpath_command rpath_command;
    struct linkedit_data_command linkedit_data_command;
    struct encryption_info_command encryption_info_command;
    struct encryption_info_command_64 encryption_info_command_64;
    struct version_min_command version_min_command;
    struct dyld_info_command dyld_info_command;
    struct symseg_command symseg_command;
    struct ident_command ident_command;
    struct fvmfile_command fvmfile_command;
    struct entry_point_command entry_point_command;
    struct source_version_command source_version_command;
    struct data_in_code_entry data_in_code_entry;
    struct tlv_descriptor tlv_descriptor;

    return 0;
}
