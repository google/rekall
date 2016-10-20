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

# pylint: disable=protected-access
from rekall import obj
from rekall import utils
from rekall.plugins import core
from rekall.plugins.overlays import basic
from rekall.plugins.windows import common


class WinPhysicalMap(common.WindowsCommandPlugin):
    """Prints the boot physical memory map."""

    __name = "phys_map"

    table_header = [
        dict(name="phys_start", style="address"),
        dict(name="phys_end", style="address"),
        dict(name="pages"),
    ]

    def collect(self):
        descriptor = self.profile.get_constant_object(
            "MmPhysicalMemoryBlock",
            target="Pointer",
            target_args=dict(
                target="_PHYSICAL_MEMORY_DESCRIPTOR",
                ))

        for memory_range in descriptor.Run:
            yield (memory_range.BasePage * 0x1000,
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

    table_header = [
        dict(name="virt_start", style="address"),
        dict(name="virt_end", style="address"),
        dict(name="type", width=10),
    ]

    @classmethod
    def is_active(cls, session):
        return (super(WinVirtualMap, cls).is_active(session) and
                session.profile.get_constant('MiSystemVaType'))

    def collect(self):
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
                    yield (range_start, range_start + range_length, range_type)

                range_type = page_type
                range_start = offset
                range_length = va_table_size
            else:
                range_length += va_table_size


class Objects(common.WindowsCommandPlugin):
    """Displays all object Types on the system."""

    name = "object_types"

    table_header = [
        dict(name="type", style="address"),
        dict(name="index", align="r", width=5),
        dict(name="NumberOfObjects", align="r", width=15),
        dict(name="PoolType", width=20),
        dict(name="name")
    ]

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

    def collect(self):
        for obj_type in self.object_types():
            yield dict(type=obj_type,
                       index=obj_type.Index,
                       NumberOfObjects=obj_type.TotalNumberOfObjects,
                       PoolType=obj_type.TypeInfo.PoolType,
                       name=obj_type.Name)


class ImageInfo(common.WindowsCommandPlugin):
    """List overview information about this image."""

    name = "imageinfo"

    table_header = [
        dict(name="key", width=20),
        dict(name="value")
    ]

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

    def collect(self):
        yield ("Kernel DTB", "%#x" % self.kernel_address_space.dtb)

        for desc, name, type in (
                ("NT Build", "NtBuildLab", "String"),
                ("NT Build Ex", "NtBuildLabEx", "String"),
                ("Signed Drivers", "g_CiEnabled", "bool"),
            ):

            yield dict(
                key=desc,
                value=self.profile.get_constant_object(name, target=type))

        # Print kuser_shared things.
        kuser_shared = self.profile.get_constant_object(
            "KI_USER_SHARED_DATA", "_KUSER_SHARED_DATA")

        yield ("Time (UTC)", kuser_shared.SystemTime)

        # The bias is given in windows file time (i.e. in 100ns ticks).
        bias = kuser_shared.TimeZoneBias.cast("long long") / 1e7
        yield ("Time (Local)", kuser_shared.SystemTime.display(
            utc_shift=-bias))

        yield ("Sec Since Boot", self.GetBootTime(kuser_shared))
        yield ("NtSystemRoot", kuser_shared.NtSystemRoot)


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

        kuser_shared = profile.get_constant_object(
            "KI_USER_SHARED_DATA", "_KUSER_SHARED_DATA")

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


class ObjectTree(common.WindowsCommandPlugin):
    """Visualize the kernel object tree.

    Ref:
    http://msdn.microsoft.com/en-us/library/windows/hardware/ff557762(v=vs.85).aspx
    """

    name = "object_tree"

    __args = [
        dict(name="type_regex", default=".", type="RegEx",
             help="Filter the type of objects shown.")
    ]

    table_header = [
        dict(name="_OBJECT_HEADER", style="address"),
        dict(name="type", width=20),
        dict(name="name", type="TreeNode"),
    ]

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
            for prefix, drive_letter in self.session.GetParameter(
                    "drive_letter_device_map").iteritems():
                prefix = self.ResolveSymlinks(prefix)
                if path.startswith(prefix):
                    return drive_letter + path[len(prefix):]

        # This will be triggered if the path does not resolve to anything in the
        # object tree.
        except KeyError:
            return path

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

    def _collect_directory(self, directory, seen, depth=0):
        for obj_header in directory.list():
            if obj_header in seen:
                continue
            seen.add(obj_header)

            name = unicode(obj_header.NameInfo.Name)
            obj_type = str(obj_header.get_object_type())

            if obj_type == "SymbolicLink":
                name += u"-> %s (%s)" % (obj_header.Object.LinkTarget,
                                         obj_header.Object.CreationTime)

            if self.plugin_args.type_regex.search(obj_type):
                yield dict(_OBJECT_HEADER=obj_header, type=obj_type,
                           name=name, depth=depth)

            if obj_type == "Directory":
                for x in self._collect_directory(
                        obj_header.Object, seen, depth=depth+1):
                    yield x

    def collect(self):
        # The root object.
        root = self.GetObjectByName("/")

        seen = set()
        for x in self._collect_directory(root, seen):
            yield x


class WindowsTimes(common.WindowsCommandPlugin):
    """Return current time, as known to the kernel."""

    name = "times"

    table_header = [
        dict(name="Times"),
    ]

    def collect(self):
        kuser_shared = self.session.address_resolver.get_constant_object(
            "nt!KI_USER_SHARED_DATA", "_KUSER_SHARED_DATA")

        seconds_since_boot = self.session.plugins.imageinfo().GetBootTime(
            kuser_shared)

        kernel_time = kuser_shared.SystemTime
        boot_timestamp = basic.UnixTimeStamp(
            value=kernel_time - seconds_since_boot,
            session=self.session)

        yield [utils.AttributeDict(now=kernel_time, boot=boot_timestamp,
                                   uptime=seconds_since_boot)]
