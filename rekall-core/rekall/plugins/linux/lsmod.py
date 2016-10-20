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
from rekall.plugins.linux import common



class Lsmod(common.LinuxPlugin):
    '''Gathers loaded kernel modules.'''
    name = "lsmod"

    table_header = [
        dict(name="virtual", style="address"),
        dict(name="start", style="address"),
        dict(name="size", width=10),
        dict(name="name", width=20)
    ]

    def get_module_list(self):
        modules = self.profile.get_constant_object(
            "modules", target="list_head", vm=self.kernel_address_space)

        # walk the modules list
        for module in modules.list_of_type("module", "list"):
            yield module

    def collect(self):
        for module in self.get_module_list():
            yield (module.obj_offset,
                   module.module_core.deref(),
                   module.init_size + module.core_size,
                   module.name)


class LsmodSections(common.LinuxPlugin):
    """Display all the ELF sections of kernel modules."""

    name = "lsmod_sections"

    table_header = [
        dict(name="name", width=20),
        dict(name="section", width=30),
        dict(name="address", style="address")
    ]

    def get_module_sections(self, module):
        num_sects = module.sect_attrs.nsections
        for i in range(num_sects):
            section_attr = module.sect_attrs.attrs[i]
            yield section_attr

    def collect(self):
        lsmod = self.session.plugins.lsmod()
        for module in lsmod.get_module_list():
            for section_attr in self.get_module_sections(module):
                yield (module.name, section_attr.name.deref(),
                       section_attr.address)

class Lsmod_parameters(common.LinuxPlugin):
    """Display parameters for all kernel modules."""
    name = "lsmod_parameters"

    _arg_lookuptable = {
        "linux!param_get_bool": ("bool", {}),
        "linux!param_get_byte": ("char", {}),
        "linux!param_get_charp": ("Pointer", dict(target="String")),
        "linux!param_get_int": ("int", {}),
        "linux!param_get_invbool": ("byte", {}),
        "linux!param_get_long": ("long", {}),
        "linux!param_get_short": ("short", {}),
        "linux!param_get_uint": ("unsigned int", {}),
        "linux!param_get_ulong": ("unsigned long", {}),
        "linux!param_get_ushort": ("unsigned short", {}),
    }

    table_header = [
        dict(name="name", width=20),
        dict(name="key", width=40),
        dict(name="value", width=20)
    ]

    def __init__(self, *args, **kwargs):
        super(Lsmod_parameters, self).__init__(*args, **kwargs)
        self.arg_lookuptable = {}
        resolver = self.session.address_resolver
        for x, y in self._arg_lookuptable.items():
            try:
                address = resolver.get_constant_object(
                    x, "Function").obj_offset
                self.arg_lookuptable[address] = y
            except ValueError:
                pass

    def get_module_parameters(self, module):
        for kernel_param in module.m("kp"):
            getter_function = self.profile.Function(
                offset=kernel_param.getter_addr,
                vm=self.kernel_address_space)

            value = None
            lookup = self.arg_lookuptable.get(kernel_param.getter_addr)
            if lookup:
                type, args = lookup

                # The arg type is a pointer to a basic type.
                value = kernel_param.m("u1").arg.dereference_as(
                    target=type, target_args=args)

            elif getter_function == self.profile.get_constant_object(
                    "param_get_string", target="Function",
                    vm=self.kernel_address_space):

                value = kernel_param.m("u1").str.deref().v()

            #It is an array of values.
            elif getter_function == self.profile.get_constant_object(
                    "param_array_get", target="Function",
                    vm=self.kernel_address_space):

                array = kernel_param.m("u1").arr

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
                value = self.session.address_resolver.format_address(
                             getter_function)

            yield kernel_param.name.deref(), value

    def collect(self):
        lsmod = self.session.plugins.lsmod()
        for module in lsmod.get_module_list():
            for key, value in self.get_module_parameters(module):
                yield (module.name, key, value)


class Moddump(common.LinuxPlugin):
    '''Dumps loaded kernel modules.'''
    __name = "moddump"

    __args = [
        dict(name="dump_dir", help="Dump directory.",
             required=True),

        dict(name="regexp", default=None, type="RegEx",
             help="Regexp on the module name.")
    ]

    def dump_module(self, module):
        module_start = int(module.module_core)
        return module.obj_vm.read(module_start, module.core_size)

    def render(self, renderer):
        lsmod_plugin = self.session.plugins.lsmod(session=self.session)
        for module in lsmod_plugin.get_module_list():
            if self.plugin_args.regexp:
                if not module.name:
                    continue

                if not self.plugin_args.regexp.search(module.name):
                    continue

            file_name = "{0}.{1:#x}.lkm".format(module.name,
                                                module.module_core)
            with renderer.open(directory=self.plugin_args.dump_dir,
                               filename=file_name,
                               mode="wb") as mod_file:

                mod_data = self.dump_module(module)
                mod_file.write(mod_data)
                renderer.format("Wrote {0} bytes to {1}\n",
                                module.core_size, file_name)
