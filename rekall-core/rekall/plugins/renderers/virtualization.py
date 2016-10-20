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

"""This module implements renderers specific to virtualization."""

from rekall import utils
from rekall.ui import renderer
from rekall.ui import text
from rekall.ui import json_renderer
from rekall.plugins import hypervisors
from rekall.plugins.renderers import data_export
from rekall.plugins.renderers import json_storage


class VTxPagedMemoryObjectRenderer(
    json_storage.BaseAddressSpaceObjectRenderer):
    renders_type = "VTxPagedMemory"

    def GetState(self, item, **options):
        state = super(VTxPagedMemoryObjectRenderer, self).GetState(
            item, **options)
        state["dtb"] = item.dtb
        state["ept"] = item.ept

        return state

class VirtualMachine_DataExportRenderer(data_export.DataExportObjectRenderer):
    renders_type = "VirtualMachine"

    def EncodeToJsonSafe(self, vm, **options):
        result = super(VirtualMachine_DataExportRenderer,
                       self).EncodeToJsonSafe(vm)
        result["ept"] = vm.ept
        result["host_rip"] = vm.host_rip
        result["name"] = vm.name
        result["_quick"] = options.pop("quick", False)
        result["guest_arch"] = vm.guest_arch
        result["num_cores"] = vm.num_cores
        # The VMCSs are stored in a set.
        result["vmcss"] = list(vm.vmcss)
        result["virtual_machines"] = list(vm.virtual_machines)

        return json_renderer.JsonObjectRenderer.EncodeToJsonSafe(self, result)

    def Summary(self, vm, **_):
        if vm.get("_quick"):
            return "VM [?? vCORE(s), {1}]".format(vm.get("guest_arch"))
        else:
            return "VM [{0} vCORE(s), {1}]".format(
                vm.get("num_cores"), vm.get("guest_arch"))


class VirtualMachine_JsonObjectRenderer(json_renderer.StateBasedObjectRenderer):
    renders_type = "VirtualMachine"

    def DecodeFromJsonSafe(self, state, options):
        super_obj = super(VirtualMachine_JsonObjectRenderer, self)
        state = super_obj.DecodeFromJsonSafe(state, options)

        vm = hypervisors.VirtualMachine(host_rip=state.get("host_rip"),
                                        ept=state.get("ept"),
                                        parent=state.get("parent"),
                                        name=state.get("name"),
                                        session=state.get("base_session"))

        vm.vmcss = state.get("vmcss", [])
        vm.vmcs_validation = state.get("vmcs_validation", {})

        # Decode each nested VirtualMachine
        for vm in state.get("virtual_machines", []):
            unserialized_vm = self.DecodeFromJsonSafe(vm, options)
            unserialized_vm.parent = vm
            vm.virtual_machines.update([unserialized_vm])
        return vm

    def GetState(self, item, **options):
        state = super(VirtualMachine_JsonObjectRenderer, self).GetState(
            item, **options)
        state["_quick"] = options.pop("quick", False)
        state["ept"] = item.ept
        state["host_rip"] = item.host_rip
        state["name"] = item.name
        state["base_session"] = item.base_session
        # The validation state is stored as a dict of vmcs:state pairs.
        state["vmcs_validation"] = item.vmcs_validation
        # The VMCSs are stored in a set.
        state["vmcss"] = list(item.vmcss)
        state["virtual_machines"] = list(item.virtual_machines)
        return state


class VirtualizationNode_TextObjectRenderer(text.TextObjectRenderer):
    """Virtualization nodes can be Hypervisors, VirtualMachine or VMCS."""
    renders_type = "VirtualizationNode"
    renderers = ["TextRenderer", "WebConsoleRenderer", "TestRenderer"]

    def __init__(self, *args, **options):
        self.quick = options.pop("quick", False)
        super(VirtualizationNode_TextObjectRenderer, self).__init__(
            *args, **options)

        self.table = text.TextTable(
            columns=[
                dict(name="description"),
                dict(name="name", width=20),
                dict(name="valid", type="bool"),
                dict(name="ept")],
            renderer=self.renderer,
            session=self.session)

    def render_header(self, **options):
        result = text.Cell("Description", width=40)
        result.append_line("-" * result.width)

        return result

    def render_row(self, target, **options):
        if isinstance(target, hypervisors.VirtualMachine):
            return text.Cell("VM [{0:s} vCORE(s), {1:s}]".format(
                (self.quick and "??") or str(target.num_cores),
                target.guest_arch))
        elif "VMCS" in target.__class__.__name__:
            return text.Cell("VMCS @ {0:08X} vCORE {1:x}".format(
                target.obj_offset, target.m("VPID")))
