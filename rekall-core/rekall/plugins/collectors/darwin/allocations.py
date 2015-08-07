# Rekall Memory Forensics
#
# Copyright 2015 Google Inc. All Rights Reserved.
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

"""
Darwin heap & VAD collectors.
"""
__author__ = "Adam Sindelar <adamsh@google.com>"

from rekall import obj

from rekall.entities import definitions

from rekall.plugins.collectors.darwin import common


class DarwinProcessVADs(common.DarwinEntityCollector):
    """Produces process virtual memory descriptors.

    Works by basically walking the vm_map_entry structs in each proc struct's
    task map, and making lots of inferences based on the values in that and
    related structures.

    Most of the actual derivation logic is in the overlay.
    """

    outputs = ["MemoryDescriptor", "AddressSpace", "Struct/type=vm_map_entry"]

    collect_args = dict(procs="has component Process")
    enforce_hint = True

    PROTECTION_FLAGS = {
        "VM_PROT_READ": "read",
        "VM_PROT_WRITE": "write",
        "VM_PROT_EXECUTE": "execute"}

    def collect(self, hint, procs):
        # We're going to have a much better time if we can ignore processes
        # that aren't relevant.
        hint_filter = hint.run_engine("hinter",
                                      selector="MemoryDescriptor/process")

        for proc in procs:
            if (hint_filter and not
                    hint_filter.run_engine("matcher", bindings=proc)):
                continue

            vm = proc["Struct/base"].get_process_address_space()
            arch = "x86_32" if vm.end() <= 0x1000000000 else "x86_64"

            vm_identity, vm_entity = self.prebuild(
                components=[definitions.AddressSpace(dtb=vm.dtb,
                                                     type="virtual",
                                                     architecture=arch,
                                                     owner=proc.identity),
                            definitions.Named(kind="Virtual Address Space",
                                              name="DTB @%#016x" % vm.dtb)],
                keys=("AddressSpace/dtb",))

            yield vm_entity

            for address in proc["Struct/base"].task.map.hdr.walk_list(
                    "links.next", include_current=False):

                # Is this range backed by a vnode? If so yield it, and save the
                # identity. This should take care of __TEXT, __LINKEDIT and
                # memory mapped sections.
                vnode = address.find_vnode_object()
                file_identity = None
                if vnode:
                    file_identity, file = self.prebuild(
                        components=[definitions.Struct(base=vnode,
                                                       type="vnode")],
                        keys=("Struct/base",))
                    yield file

                # Sort out permission bits.
                perms = []
                max_perms = []
                for flag in address.protection:
                    perm = self.PROTECTION_FLAGS.get(flag)
                    if not perm:
                        raise ValueError("Unknown protection flag %r." % flag)
                    perms.append(perm)

                for flag in address.max_protection:
                    perm = self.PROTECTION_FLAGS.get(flag)
                    if not perm:
                        raise ValueError("Unknown protection flag %r." % flag)
                    max_perms.append(perm)

                # Sort out shared memory flags.
                sharing_mode = address.sharing_mode
                sharing_enum = None
                if sharing_mode in ("SM_SHARED", "SM_LARGE_PAGE"):
                    sharing_enum = "shared"
                elif sharing_mode == "SM_COW":
                    sharing_enum = "copy-on-write"
                elif sharing_mode == "SM_PRIVATE":
                    sharing_enum = "private"
                elif sharing_mode == "SM_EMPTY":
                    sharing_enum = None
                else:
                    raise ValueError("Unknown sharing mode %r." % sharing_mode)

                _, result = self.prebuild(
                    components=[
                        definitions.MemoryDescriptor(
                            start=obj.Void(vm=vm,
                                           profile=self.session.profile,
                                           offset=address.links.start.v()),
                            end=obj.Void(vm=vm,
                                         profile=self.session.profile,
                                         offset=address.links.end.v()),
                            address_space=vm_identity,
                            permissions=perms,
                            max_permissions=max_perms,
                            file=file_identity,
                            shared=sharing_enum,
                            code_signed=address.code_signed),
                        definitions.Struct(
                            base=address,
                            type="vm_map_entry")],
                    keys=("MemoryDescriptor/address_space",
                          "MemoryDescriptor/start",
                          "MemoryDescriptor/end"))

                yield result
