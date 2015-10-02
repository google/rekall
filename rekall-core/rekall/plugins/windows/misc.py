# Rekall Memory Forensics
#
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
"""Miscelaneous information gathering plugins."""

__author__ = "Michael Cohen <scudette@google.com>"
import hashlib
import re

# pylint: disable=protected-access
from rekall import obj
from rekall import utils
from rekall.plugins import core
from rekall.plugins.windows import common


class WinPhysicalMap(common.WindowsCommandPlugin):
    """Prints the boot physical memory map."""

    __name = "phys_map"

    def render(self, renderer):
        renderer.table_header([
            ("Phys Start", "phys", "[addrpad]"),
            ("Phys End", "phys", "[addrpad]"),
            ("Number of Pages", "pages", ""),
            ])

        descriptor = self.profile.get_constant_object(
            "MmPhysicalMemoryBlock",
            target="Pointer",
            target_args=dict(
                target="_PHYSICAL_MEMORY_DESCRIPTOR",
                ))

        for memory_range in descriptor.Run:
            renderer.table_row(
                memory_range.BasePage * 0x1000,
                (memory_range.BasePage + memory_range.PageCount) * 0x1000,
                memory_range.PageCount)


class WindowsSetProcessContext(core.SetProcessContextMixin,
                               common.WinProcessFilter):
    """A cc plugin for windows."""


class WinVirtualMap(common.WindowsCommandPlugin):
    """Prints the Windows Kernel Virtual Address Map.

    On 32 bit windows, the kernel virtual address space can be managed
    dynamically. This plugin shows each region and what it is used for.

    Note that on 64 bit windows the address space is large enough to not worry
    about it. In that case, the offsets and regions are hard coded.

    http://www.woodmann.com/forum/entry.php?219-Using-nt!_MiSystemVaType-to-navigate-dynamic-kernel-address-space-in-Windows7
    """

    __name = "virt_map"

    @classmethod
    def is_active(cls, session):
        return (super(WinVirtualMap, cls).is_active(session) and
                session.profile.get_constant('MiSystemVaType'))

    def render(self, renderer):
        renderer.table_header([
            ("Virtual Start", "virt_start", "[addrpad]"),
            ("Virtual End", "virt_end", "[addrpad]"),
            ("Type", "type", "10"),
            ])

        system_va_table = self.profile.get_constant_object(
            "MiSystemVaType",
            target="Array",
            target_args=dict(
                target="Enumeration",
                target_args=dict(
                    target="byte",
                    enum_name="_MI_SYSTEM_VA_TYPE"
                    ),
                )
            )

        system_range_start = self.profile.get_constant_object(
            "MiSystemRangeStart", "unsigned int")

        # The size varies on PAE profiles.
        va_table_size = 0x1000 * 0x1000 / self.profile.get_obj_size("_MMPTE")

        # Coalesce the ranges.
        range_type = range_start = range_length = 0

        for offset in range(system_range_start, 0xffffffff, va_table_size):
            table_index = (offset - system_range_start) / va_table_size
            page_type = system_va_table[table_index]
            if page_type != range_type:
                if range_type:
                    renderer.table_row(
                        range_start, range_start + range_length, range_type)

                range_type = page_type
                range_start = offset
                range_length = va_table_size
            else:
                range_length += va_table_size


class Objects(common.WindowsCommandPlugin):
    """Displays all object Types on the system."""

    name = "object_types"

    def object_types(self):
        # The size of the type array depends on the operating system and it is
        # hard coded. We can find out the size by seeing how many Type objects
        # were allocated.
        type_table = self.profile.get_constant_object(
            "ObpObjectTypes",
            target="Array", target_args=dict(
                target="Pointer",
                count=0,
                target_args=dict(
                    target="_OBJECT_TYPE")
                )
            )

        type_type = type_table[0]  # The "Type" object.
        type_table.count = type_type.TotalNumberOfObjects

        for t in type_table:
            if t:
                yield t

    def render(self, renderer):
        renderer.table_header([
            ("Type", "type", "[addrpad]"),
            ("Index", "idx", ">5"),
            ("Number Objects", "TotalNumberOfObjects", ">15"),
            ("PoolType", "PoolType", "20"),
            ("Name", "name", "")])

        for obj_type in self.object_types():
            renderer.table_row(
                obj_type,
                obj_type.Index,
                obj_type.TotalNumberOfObjects,
                obj_type.TypeInfo.PoolType,
                obj_type.Name)


class ImageInfo(common.WindowsCommandPlugin):
    """List overview information about this image."""

    name = "imageinfo"

    @staticmethod
    def KeQueryTimeIncrement(profile):
        """Return the time of each tick (float).

        dis "nt!KeQueryTimeIncrement"
        ------ nt!KeQueryTimeIncrement ------
        MOV EAX, [RIP+0x24af66]        0x26161 nt!KeMaximumIncrement
        RET
        """
        return profile.get_constant_object(
            "KeMaximumIncrement", target="unsigned int") * 100e-9

    def GetBootTime(self, kuser_shared):
        """Returns the number of seconds since boot.
        Ref:
        KeQueryTickCount * KeQueryTimeIncrement

        reactos/include/ddk/wdm.h:

        #define SharedTickCount         (KI_USER_SHARED_DATA + 0x320)

        #define KeQueryTickCount(CurrentCount) \
          *(ULONG64*)(CurrentCount) = *(volatile ULONG64*)SharedTickCount
        """
        current_tick_count = (
            int(kuser_shared.TickCountQuad) or  # Win7
            int(kuser_shared.TickCountLow))     # WinXP

        return current_tick_count * self.KeQueryTimeIncrement(self.profile)

    def render(self, renderer):
        renderer.table_header([("Fact", "key", "20"),
                               ("Value", "value", "30")])

        renderer.table_row(
            "Kernel DTB", "%#x" % self.kernel_address_space.dtb)

        for desc, name, type in (
                ("NT Build", "NtBuildLab", "String"),
                ("NT Build Ex", "NtBuildLabEx", "String"),
                ("Signed Drivers", "g_CiEnabled", "bool"),
            ):

            renderer.table_row(
                desc, self.profile.get_constant_object(name, target=type))

        # Print kuser_shared things.
        kuser_shared = self.profile._KUSER_SHARED_DATA(
            self.profile.get_constant("KI_USER_SHARED_DATA"))

        renderer.table_row("Time (UTC)", kuser_shared.SystemTime)

        # The bias is given in windows file time (i.e. in 100ns ticks).
        bias = kuser_shared.TimeZoneBias.cast("long long") / 1e7
        renderer.table_row("Time (Local)", kuser_shared.SystemTime.display(
            utc_shift=-bias))

        renderer.table_row("Sec Since Boot", self.GetBootTime(kuser_shared))
        renderer.table_row("NtSystemRoot", kuser_shared.NtSystemRoot)

        renderer.section("Physical Layout")
        self.session.plugins.phys_map().render(renderer)


class WinImageFingerprint(common.AbstractWindowsParameterHook):
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
        if not self.session.physical_address_space:
            return None

        if self.session.physical_address_space.volatile:
            return obj.NoneObject("No fingerprint for volatile image.")

        result = []
        profile = self.session.profile
        phys_as = self.session.physical_address_space

        address_space = self.session.GetParameter("default_address_space")

        label = profile.get_constant_object("NtBuildLab", "String")
        result.append((address_space.vtop(label.obj_offset), label.v()))

        label = profile.get_constant_object("NtBuildLabEx", "String")
        result.append((address_space.vtop(label.obj_offset), label.v()))

        kuser_shared = profile._KUSER_SHARED_DATA(
            profile.get_constant("KI_USER_SHARED_DATA"))

        system_time_offset = address_space.vtop(
            kuser_shared.SystemTime.obj_offset)

        result.append((system_time_offset, phys_as.read(system_time_offset, 8)))

        tick_time_offset = address_space.vtop(
            kuser_shared.multi_m("TickCountQuad", "TickCountLow").obj_offset)
        result.append((tick_time_offset, phys_as.read(tick_time_offset, 8)))

        # List of processes should also be pretty unique.
        for task in self.session.plugins.pslist().filter_processes():
            name = task.name.cast("String", length=30)
            task_name_offset = address_space.vtop(name.obj_offset)

            # Read the raw data for the task name. Usually the task name is
            # encoded in utf8 but then we might not be able to compare it
            # exactly - we really want bytes here.
            result.append((task_name_offset, name.v()))

        return dict(
            hash=hashlib.sha1(unicode(result).encode("utf8")).hexdigest(),
            tests=result)


class Pools(common.WindowsCommandPlugin):
    """Prints information about system pools.

    Ref:
    http://illmatics.com/Windows%208%20Heap%20Internals.pdf
    https://media.blackhat.com/bh-dc-11/Mandt/BlackHat_DC_2011_Mandt_kernelpool-wp.pdf
    https://immunityinc.com/infiltrate/archives/kernelpool_infiltrate2011.pdf
    http://gate.upm.ro/os/LABs/Windows_OS_Internals_Curriculum_Resource_Kit-ACADEMIC/WindowsResearchKernel-WRK/WRK-v1.2/base/ntos/ex/pool.c
    """

    name = "pools"

    def find_all_pool_descriptors(self):
        """Finds all unique pool descriptors."""
        descriptors = set()

        vector_pool = self.profile.get_constant_object(
            "PoolVector",
            target="Array",
            target_args=dict(
                count=2,
                target="Pointer",
                )
            )

        # Non paged pool.
        for desc in vector_pool[0].dereference_as(
                "Array",
                target_args=dict(
                    count=self.profile.get_constant_object(
                        "ExpNumberOfNonPagedPools", "unsigned int").v(),
                    target="_POOL_DESCRIPTOR",
                    )
            ):
            desc.PoolStart = self.profile.get_constant_object(
                "MmNonPagedPoolStart", "Pointer")
            desc.PoolEnd = (
                desc.PoolStart.v() +
                self.profile.get_constant_object(
                    "MmMaximumNonPagedPoolInBytes", "unsigned int"))
            descriptors.add(desc)

        # Paged pool.
        paged_pool_start = self.profile.get_constant_object(
            "MmPagedPoolStart", "unsigned int").v()

        comment = ""
        if not paged_pool_start:
            if self.profile.metadata("arch") == "I386":
                # On Win7x86 the paged pool is distributed (see virt_map
                # plugin).
                comment = "Fragmented (See virt_map plugin)"
                paged_pool_start = paged_pool_end = None
            else:
                # Hard coded on Windows 7. http://www.codemachine.com/article_x64kvas.html
                # http://www.reactos.org/wiki/Techwiki:Memory_Layout
                paged_pool_start = obj.Pointer.integer_to_address(
                    0xFFFFF8A000000000)
                paged_pool_end = obj.Pointer.integer_to_address(
                    0xFFFFF8CFFFFFFFFF)
        else:
            paged_pool_end = (
                paged_pool_start + self.profile.get_constant_object(
                    "MmSizeOfPagedPoolInBytes", "address").v())

        for desc in vector_pool[1].dereference_as(
                "Array",
                target_args=dict(
                    count=self.profile.get_constant_object(
                        "ExpNumberOfPagedPools", "unsigned int").v() + 1,
                    target="_POOL_DESCRIPTOR",
                )
            ):
            # Hard coded for 64 bit OS.
            desc.PoolStart = paged_pool_start
            desc.PoolEnd = paged_pool_end
            desc.Comment = comment
            descriptors.add(desc)

        # Add session pools.
        for task in self.session.plugins.pslist().list_eprocess():
            desc = task.Session.PagedPool
            if desc:
                desc.PoolStart = task.Session.PagedPoolStart
                desc.PoolEnd = task.Session.PagedPoolEnd
                descriptors.add(desc)

                desc.Comment = "Session ID %s" % task.Session.SessionId

        return descriptors

    def render(self, renderer):
        descriptors = self.find_all_pool_descriptors()
        renderer.table_header([
            ("Type", "type", "20"),
            ("Index", "index", "5"),
            ("Size", "total_bytes", ">10"),
            ("Start", "start", "[addrpad]"),
            ("End", "end", "[addrpad]"),
            ("Comment", "comment", "s")])

        for desc in sorted(descriptors):
            renderer.table_row(
                desc.PoolType,
                desc.PoolIndex,
                desc.m("TotalBytes") or desc.TotalPages * 0x1000,
                desc.PoolStart,
                desc.PoolEnd,
                getattr(desc, "Comment", ""))


class PoolTracker(common.WindowsCommandPlugin):
    """Enumerate pool tag usage statistics."""

    name = "pool_tracker"

    def render(self, renderer):
        table = self.profile.get_constant_object(
            "PoolTrackTable",
            target="Pointer",
            target_args=dict(
                target="Array",
                target_args=dict(
                    count=self.profile.get_constant_object(
                        "PoolTrackTableSize", "unsigned int").v(),
                    target="_POOL_TRACKER_TABLE",
                    )
                )
            )

        renderer.table_header(
            columns=[("Tag", "tag", "4"),
                     ("NP Alloc", "nonpaged", ">20"),
                     ("NP Bytes", "nonpaged_bytes", ">10"),
                     ("P Alloc", "nonpaged", ">20"),
                     ("P Bytes", "nonpaged_bytes", ">10"),
                    ],
            sort=("tag",)
            )

        for item in table:
            if item.Key == 0:
                continue

            self.session.report_progress()
            renderer.table_row(
                # Show the pool tag as ascii.
                item.Key.cast("String", length=4),
                "%s (%s)" % (item.NonPagedAllocs,
                             item.NonPagedAllocs - item.NonPagedFrees),
                item.NonPagedBytes,
                "%s (%s)" % (item.PagedAllocs,
                             item.PagedAllocs - item.PagedFrees),
                item.PagedBytes,
                )


class ObjectTree(common.WindowsCommandPlugin):
    """Visualize the kernel object tree.

    Ref:
    http://msdn.microsoft.com/en-us/library/windows/hardware/ff557762(v=vs.85).aspx
    """

    name = "object_tree"

    @classmethod
    def args(cls, parser):
        """Declare the command line args we need."""
        super(ObjectTree, cls).args(parser)
        parser.add_argument("--type_regex", default=".",
                            help="Filter the type of objects shown.")

    def __init__(self, type_regex=None, **kwargs):
        super(ObjectTree, self).__init__(**kwargs)

        if type_regex:
            type_regex = re.compile(type_regex)
        self.type_regex = type_regex

    def GetObjectByName(self, path):
        root = self.session.GetParameter("object_tree")
        for component in utils.SplitPath(path):
            root = root["Children"][component]

        return self.profile.Object(type_name=root["type_name"],
                                   offset=root["offset"])

    def FileNameWithDrive(self, path):
        """Tries to resolve the path back to something with a drive letter."""
        # First normalize the path.
        try:
            path = self.ResolveSymlinks(path)

        # This will be triggered if the path does not resolve to anything in the
        # object tree.
        except KeyError:
            return path

        for prefix, drive_letter in self.session.GetParameter(
                "drive_letter_device_map").iteritems():
            prefix = self.ResolveSymlinks(prefix)
            if path.startswith(prefix):
                return drive_letter + path[len(prefix):]

    def ResolveSymlinks(self, path):
        """Takes a path and resolves any intermediate symlinks in it.

        Returns:
          A direct path to the object.
        """
        components = path.split("\\")
        return "\\".join(self._parse_path_components(components))

    def _parse_path_components(self, components):
        node = self.session.GetParameter("object_tree")
        new_components = []

        for i, component in enumerate(components):
            if not component:
                continue

            if component == "??":
                component = "GLOBAL??"

            next_node = utils.CaseInsensitiveDictLookup(
                component, node["Children"])

            # If the first component is not found, search for it in the global
            # namespace.
            if next_node is None and i == 0 and component != "GLOBAL??":
                return self._parse_path_components(["GLOBAL??"] + components)

            if next_node is None:
                raise KeyError(
                    "component %r not found at %s" % (
                        component, "\\".join(new_components)))

            elif next_node["type"] == "SymbolicLink":
                object_header = self.session.profile._OBJECT_HEADER(
                    next_node["offset"])

                target = object_header.Object.LinkTarget.v()

                # Append the next components to the target and re-parse
                return self._parse_path_components(
                    target.split("\\") + components[i+1:])

            elif next_node["type"] != "Directory":
                return new_components + components[i:]

            new_components.append(component)
            node = next_node

        return new_components

    def _render_directory(self, directory, renderer, seen, depth=0):
        for obj_header in directory.list():
            if obj_header in seen:
                continue
            seen.add(obj_header)

            name = unicode(obj_header.NameInfo.Name)
            obj_type = str(obj_header.get_object_type())

            if obj_type == "SymbolicLink":
                name += u"-> %s (%s)" % (obj_header.Object.LinkTarget,
                                         obj_header.Object.CreationTime)

            if self.type_regex is None or self.type_regex.search(obj_type):
                renderer.table_row(obj_header, obj_type, name, depth=depth)

            if obj_type == "Directory":
                self._render_directory(
                    obj_header.Object, renderer, seen, depth=depth+1)

    def render(self, renderer):
        renderer.table_header([("_OBJECT_HEADER", "offset", "[addrpad]"),
                               ("Type", "type", "20"),
                               dict(name="Name", type="TreeNode"),
                              ])

        # The root object.
        root = self.GetObjectByName("/")

        seen = set()
        self._render_directory(root, renderer, seen)
