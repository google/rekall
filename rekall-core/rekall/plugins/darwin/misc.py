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
"""Miscelaneous information gathering plugins."""

__author__ = "Michael Cohen <scudette@google.com>"
import hashlib
import re

from rekall import obj
from rekall.plugins import core
from rekall.plugins.darwin import common
from rekall.plugins.renderers import visual_aides


class DarwinDMSG(common.AbstractDarwinCommand):
    """Print the kernel debug messages."""

    __name = "dmesg"

    def render(self, renderer):
        renderer.table_header([
            ("Message", "message", "<80")])

        # This is a circular buffer with the write pointer at the msg_bufx
        # member.
        msgbuf = self.profile.get_constant_object(
            "_msgbufp",
            target="Pointer",
            target_args=dict(
                target="msgbuf"
            )
        )

        # Make sure the buffer is not too large.
        size = min(msgbuf.msg_size, 0x400000)
        if 0 < msgbuf.msg_bufx < size:
            data = self.kernel_address_space.read(msgbuf.msg_bufc, size)
            data = data[msgbuf.msg_bufx: size] + data[0:msgbuf.msg_bufx]
            data = re.sub("\x00", "", data)

            for x in data.splitlines():
                renderer.table_row(x)


class DarwinMachineInfo(common.AbstractDarwinCommand):
    """Show information about this machine."""

    __name = "machine_info"

    def render(self, renderer):
        renderer.table_header([("Attribute", "attribute", "20"),
                               ("Value", "value", "10")])

        info = self.profile.get_constant_object(
            "_machine_info", "machine_info")

        for member in info.members:
            renderer.table_row(member, info.m(member))


class DarwinMount(common.AbstractDarwinCommand):
    """Show mount points."""

    __name = "mount"

    def render(self, renderer):
        renderer.table_header([
            ("Device", "device", "30"),
            ("Mount Point", "mount_point", "60"),
            ("Type", "type", "")])

        mount_list = self.profile.get_constant_object(
            "_mountlist", "mount")

        for mount in mount_list.walk_list("mnt_list.tqe_next", False):
            renderer.table_row(mount.mnt_vfsstat.f_mntonname,
                               mount.mnt_vfsstat.f_mntfromname,
                               mount.mnt_vfsstat.f_fstypename)


class DarwinPhysicalMap(common.AbstractDarwinCommand):
    """Prints the EFI boot physical memory map."""

    __name = "phys_map"

    def render(self, renderer):
        renderer.table_header([
            ("Physical Start", "phys", "[addrpad]"),
            ("Physical End", "phys", "[addrpad]"),
            ("Virtual", "virt", "[addrpad]"),
            ("Pages", "pages", ">10"),
            ("Type", "type", "")])

        boot_params = self.profile.get_constant_object(
            "_PE_state", "PE_state").bootArgs

        # Code from:
        # xnu-1699.26.8/osfmk/i386/AT386/model_dep.c:560
        memory_map = self.profile.Array(
            boot_params.MemoryMap,
            vm=self.physical_address_space,
            target="EfiMemoryRange",
            target_size=int(boot_params.MemoryMapDescriptorSize),
            count=(boot_params.MemoryMapSize /
                   boot_params.MemoryMapDescriptorSize))

        runs = []
        for memory_range in memory_map:
            start = memory_range.PhysicalStart
            end = (memory_range.PhysicalStart
                   + 0x1000
                   * memory_range.NumberOfPages)
            runs.append(dict(
                value=unicode(memory_range.Type), start=start, end=end))
            renderer.table_row(
                start,
                end,
                memory_range.VirtualStart.cast("Pointer"),
                memory_range.NumberOfPages,
                memory_range.Type)

        # Render a heatmap.

        # Automatically lower resolution for large images.
        resolution = 0x1000 * 0x10  # 16 pages - conservative start.
        column_count = 12
        end = runs[-1]["end"]
        # Keep it under 200 rows.
        while end / resolution / column_count > 200:
            resolution *= 2

        notes = ("Resolution: %(pages)d pages (%(mb).2f MB) per cell.\n"
                 "Note that colors of overlapping regions are blended "
                 "using a weighted average. Letters in cells indicate "
                 "which regions from the legend are present. They are "
                 "ordered proportionally, by their respective page "
                 "counts in each cell.") % dict(pages=resolution / 0x1000,
                                                mb=resolution / 1024.0 ** 2)

        legend = visual_aides.MapLegend(
            notes=notes,
            legend=[("Am", "kEfiACPIMemoryNVS", (0x00, 0xff, 0x00)),
                    ("Ar", "kEfiACPIReclaimMemory", (0xc7, 0xff, 0x50)),
                    ("Bc", "kEfiBootServicesCode", (0xff, 0xa5, 0x00)),
                    ("Bd", "kEfiBootServicesData", (0xff, 0x00, 0x00)),
                    ("M", "kEfiConventionalMemory", (0xff, 0xff, 0xff)),
                    ("Ec", "kEfiLoaderCode", (0x00, 0xff, 0xff)),
                    ("Ed", "kEfiLoaderData", (0x00, 0x00, 0xff)),
                    ("I", "kEfiMemoryMappedIO", (0xff, 0xff, 0x00)),
                    ("X", "kEfiReservedMemoryType", (0x00, 0x00, 0x00)),
                    ("Rc", "kEfiRuntimeServicesCode", (0xff, 0x00, 0xff)),
                    ("Rd", "kEfiRuntimeServicesData", (0xff, 0x00, 0x50))])

        heatmap = visual_aides.RunBasedMap(
            caption="Offset (p)",
            legend=legend,
            runs=runs,
            resolution=resolution,
            column_count=column_count)

        renderer.table_header([
            dict(name="Visual mapping", width=120, style="full"),
            dict(name="Legend", orientation="vertical", style="full",
                 width=40)])

        renderer.table_row(heatmap, legend)


class DarwinBootParameters(common.AbstractDarwinCommand):
    """Prints the kernel command line."""

    name = "boot_cmdline"

    table_header = [
        dict(name="cmdline", type="str"),
    ]

    def collect(self):
        boot_args = self.profile.get_constant_object(
            "_PE_state", "PE_state").bootArgs

        yield dict(cmdline=boot_args.CommandLine.cast("String"))


class DarwinSetProcessContext(core.SetProcessContextMixin,
                              common.ProcessFilterMixin,
                              common.AbstractDarwinCommand):
    """A cc plugin for windows."""


class DarwinVtoP(core.VtoPMixin, common.ProcessFilterMixin,
                 common.AbstractDarwinCommand):
    """Describe virtual to physical translation on darwin platforms."""


class DarwinImageFingerprint(common.AbstractDarwinParameterHook):
    """Fingerprint the current image.

    This parameter tries to get something unique about the image quickly. The
    idea is that two different images (even of the same system at different
    points in time) will have very different fingerprints. The fingerprint is
    used as a key to cache persistent information about the system.

    Live systems can not have a stable fingerprint and so return a NoneObject()
    here.

    We return a list of tuples:
       (physical_offset, expected_data)

    The list uniquely identifies the image. If one were to read all physical
    offsets and find the expected_data at these locations, then we have a very
    high level of confidence that the image is unique and matches the
    fingerprint.
    """
    name = "image_fingerprint"

    def calculate(self):
        if self.session.physical_address_space.volatile:
            return obj.NoneObject("No fingerprint for volatile image.")

        result = []
        profile = self.session.profile
        phys_as = self.session.physical_address_space

        address_space = self.session.GetParameter("default_address_space")

        label = profile.get_constant_object("_osversion", "String")
        result.append((address_space.vtop(label.obj_offset), label.v()))

        label = profile.get_constant_object("_version", "String")
        result.append((address_space.vtop(label.obj_offset), label.v()))

        label = profile.get_constant_object("_sched_tick", "String",
                                            length=8, term=None)
        result.append((address_space.vtop(label.obj_offset), label.v()))

        catfish_offset = self.session.GetParameter("catfish_offset")
        result.append((catfish_offset, phys_as.read(catfish_offset, 8)))

        # List of processes should also be pretty unique.
        for task in self.session.plugins.pslist().filter_processes():
            name = task.name.cast("String", length=30)
            task_name_offset = address_space.vtop(name.obj_offset)

            result.append((task_name_offset, name.v()))

        return dict(
            hash=hashlib.sha1(unicode(result).encode("utf8")).hexdigest(),
            tests=result)


class DarwinHighestUserAddress(common.AbstractDarwinParameterHook):
    """The highest address for user mode/kernel mode division."""

    name = "highest_usermode_address"

    def calculate(self):
        return 0x800000000000
