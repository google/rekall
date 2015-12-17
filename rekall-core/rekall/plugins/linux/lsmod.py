# Rekall Memory Forensics
#
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

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0 or later
@contact:      atcuno@gmail.com
@organization: Digital Forensics Solutions
"""
import re

from rekall.plugins.linux import common



class Lsmod(common.LinuxPlugin):
    '''Gathers loaded kernel modules.'''
    __name = "lsmod"

    @classmethod
    def args(cls, parser):
        """Declare the command line args we need."""
        super(Lsmod, cls).args(parser)
        parser.add_argument(
            "-S", "--sections", default=False, type="Boolean",
            help="Display section addresses.")

        parser.add_argument(
            "-P", "--parameters", default=False, type="Boolean",
            help="Display module parameters.")

    def __init__(self, sections=None, parameters=None, **kwargs):
        super(Lsmod, self).__init__(**kwargs)
        self.render_sections = sections
        self.render_parameters = parameters

        # Resolve the parameter's type based on the address of the getter
        # function.
        self.arg_lookuptable = {
            "param_get_bool": ("bool", {}),
            "param_get_byte": ("char", {}),
            "param_get_charp": ("Pointer", dict(target="String")),
            "param_get_int": ("int", {}),
            "param_get_invbool": ("byte", {}),
            "param_get_long": ("long", {}),
            "param_get_short": ("short", {}),
            "param_get_uint": ("unsigned int", {}),
            "param_get_ulong": ("unsigned long", {}),
            "param_get_ushort": ("unsigned short", {}),
            }

        self.arg_lookuptable = dict(
            (self.profile.get_constant_object(x, target="Function"), y)
            for x, y in self.arg_lookuptable.items())

    def get_module_sections(self, module):
        num_sects = module.sect_attrs.nsections or 25
        for i in range(num_sects):
            section_attr = module.sect_attrs.attrs[i]
            yield section_attr

    def get_module_parameters(self, module):
        for kernel_param in module.m("kp"):
            getter_function = self.profile.Function(
                offset=kernel_param.getter_addr,
                vm=self.kernel_address_space)

            lookup = self.arg_lookuptable.get(getter_function)
            if lookup:
                type, args = lookup

                # The arg type is a pointer to a basic type.
                value = kernel_param.u1.arg.dereference_as(
                    target=type, target_args=args)

            elif getter_function == self.profile.get_constant_object(
                    "param_get_string", target="Function",
                    vm=self.kernel_address_space):

                value = kernel_param.u1.str.deref()

            #It is an array of values.
            elif getter_function == self.profile.get_constant_object(
                    "param_array_get", target="Function",
                    vm=self.kernel_address_space):

                array = kernel_param.u1.arr

                getter_function = self.profile.Function(
                    offset=array.getter_addr, vm=self.kernel_address_space)

                # Is this a known getter function?
                lookup = self.arg_lookuptable.get(getter_function)
                if lookup and array.elemsize:

                    # Decode according to this function.
                    type, args = lookup
                    result = []
                    offset = array.elem.deref().obj_offset
                    number_of_elements = array.num.deref() or array.max
                    while len(result) < number_of_elements:
                        result.append(
                            self.profile.Object(type, offset=offset,
                                                vm=self.kernel_address_space))
                        offset += array.elemsize

                    value = ",".join([str(x) for x in result])
            else:
                self.session.logging.debug("Unknown function getter %r",
                                           getter_function)
                value = None

            yield kernel_param.name.deref(), value

    def get_module_list(self):
        modules = self.profile.get_constant_object(
            "modules", target="list_head", vm=self.kernel_address_space)

        # walk the modules list
        for module in modules.list_of_type("module", "list"):
            yield module

    def render(self, renderer):
        renderer.section("Overview")
        renderer.table_header([("Virtual", "virtual", "[addrpad]"),
                               ("Core Start", "start", "[addrpad]"),
                               ("Total Size", "size", ">10"),
                               ("Name", "name", "<20")])

        for module in self.get_module_list():
            renderer.table_row(module.obj_offset,
                               module.module_core.deref(),
                               module.init_size + module.core_size,
                               module.name)

        if self.render_sections:
            renderer.section("Elf Sections")
            renderer.table_header([("Name", "name", "<20"),
                                   ("Section", "section", "<30"),
                                   ("Address", "address", "[addrpad]")])

            for module in self.get_module_list():
                for section_attr in self.get_module_sections(module):
                    renderer.table_row(
                        module.name, section_attr.name.deref(),
                        section_attr.address)

        if self.render_parameters:
            renderer.section("Module Parameters")
            renderer.table_header([("Name", "name", "<20"),
                                   ("Key", "key", "<40"),
                                   ("Value", "value", "<20")])

            for module in self.get_module_list():
                for key, value in self.get_module_parameters(module):
                    renderer.table_row(module.name, key, value)


class Moddump(common.LinuxPlugin):
    '''Dumps loaded kernel modules.'''
    __name = "moddump"

    @classmethod
    def args(cls, parser):
        """Declare the command line args we need."""
        super(Moddump, cls).args(parser)
        parser.add_argument(
            "--dump_dir", default=None, help="Dump directory.",
            required=True)
        parser.add_argument(
            "--regexp", default=None, help="Regexp on the module name.")

    def __init__(self, dump_dir=None, regexp=None, **kwargs):
        super(Moddump, self).__init__(**kwargs)
        self.dump_dir = dump_dir
        self.regexp = regexp

    def dump_module(self, module):
        module_start = int(module.module_core)
        return module.obj_vm.read(module_start, module.core_size)

    def render(self, renderer):
        lsmod_plugin = self.session.plugins.lsmod(session=self.session)
        for module in lsmod_plugin.get_module_list():
            if self.regexp:
                if not module.name:
                    continue

                if not re.search(module.name, self.regexp):
                    continue

            file_name = "{0}.{1:#x}.lkm".format(module.name,
                                                module.module_core)
            with renderer.open(directory=self.dump_dir,
                               filename=file_name,
                               mode="wb") as mod_file:

                mod_data = self.dump_module(module)
                mod_file.write(mod_data)
                renderer.format("Wrote {0} bytes to {1}\n",
                                module.core_size, file_name)
