"""Linux specific response plugins."""
import os
import platform

from rekall import addrspace
from rekall import utils

from rekall.plugins.common import address_resolver
from rekall.plugins.response import common
from rekall.plugins.response import processes
from rekall.plugins.overlays import basic


class LiveMap(utils.SlottedObject):
    __slots__ = ("start", "end", "perms", "file_offset", "dev", "inode",
                 "filename")

    @utils.safe_property
    def length(self):
        return self.end - self.start


class IRMaps(processes.APIProcessFilter):
    """Examine the process memory maps."""

    name = "maps"

    __args = [
        dict(name="regex", type="RegEx",
             help="A regular expression to filter VAD filenames."),

        dict(name="offset", type="SymbolAddress",
             help="Only print the vad corresponding to this offset."),

        dict(name="verbosity", type="IntParser", default=1,
             help="With high verbosity print more information on each region."),
    ]

    table_header = [
        dict(name='proc', type="proc", hidden=True),
        dict(name="divider", type="Divider"),
        dict(name='Map', hidden=True),
        dict(name='start', style="address"),
        dict(name='end', style="address"),
        dict(name='perms', width=4),
        dict(name='filename')
    ]

    def generate_maps(self, pid):
        # Details of this are here: http://goo.gl/fmebo
        # On linux its easy - just parse /proc/ filesystem.
        try:
            maps_data = open("/proc/%s/maps" % pid).read()
        except (OSError, IOError):
            return

        for line in maps_data.splitlines():
            result = LiveMap()
            parts = line.split()
            start, end = parts[0].split("-")
            result.start = int(start, 16)
            result.end = int(end, 16)

            result.perms = parts[1]
            result.file_offset = parts[2]
            result.dev = parts[3]
            result.inode = int(parts[4])
            try:
                result.filename = parts[5]
            except IndexError:
                pass

            yield result

    def merge_ranges(self, pid):
        """Generate merged ranges."""
        old_maps = None

        for maps in self.generate_maps(pid):
            # Try to merge this range with the previous range.
            if (old_maps and
                old_maps.end == maps.start and
                old_maps.filename == maps.filename):
                old_maps.end = maps.end
                continue

            # Yield the old range:
            if old_maps:
                yield old_maps

            old_maps = maps

        # Emit the last range.
        if old_maps:
            yield old_maps

    def collect(self):
        generator = self.generate_maps
        if self.plugin_args.verbosity <= 1:
            generator = self.merge_ranges

        for proc in self.filter_processes():
            divider = "{0} pid: {1:6}\n".format(proc.name, proc.pid)
            yield dict(divider=divider)

            for maps in generator(proc.pid):
                if (self.plugin_args.regex and not
                    self.plugin_args.regex.search(maps.filename or "")):
                    continue

                if (self.plugin_args.offset is not None and
                    not maps.start <= self.plugin_args.offset <= maps.end):
                    continue

                yield dict(proc=proc,
                           Map=maps,
                           start=maps.start,
                           end=maps.end,
                           perms=maps.perms,
                           filename=maps.filename)


class LinuxAPIProfile(common.APIBaseProfile):
    """Profile for Linux live analysis."""

    def __init__(self, proc=None, **kwargs):
        super(LinuxAPIProfile, self).__init__(**kwargs)

        # TODO: Although it is possible to run 32 bit processes on 64 bit
        # systems we dont detect this case. We set the profile architecture
        # based on the operating system's platform.
        arch, _ = platform.architecture()
        if arch == "64bit":
            basic.ProfileLP64.Initialize(self)
        else:
            basic.Profile32Bits.Initialize(self)


# Register the profile for Linux.
common.APIProfile = LinuxAPIProfile


class LinuxAPIProcessAddressSpace(addrspace.RunBasedAddressSpace):
    """An address space which read processes using ReadProcessMemory()."""

    def __init__(self, pid=None, **kwargs):
        super(LinuxAPIProcessAddressSpace, self).__init__(**kwargs)
        self.pid = pid

        try:
            self.process_handle = open("/proc/%s/mem" % pid, "rb")
            for maps in self.session.plugins.maps().merge_ranges(pid):
                self.add_run(maps.start, maps.start, maps.length,
                             address_space=self, data=dict(
                                 pid=pid, vad=maps))
        except (IOError, OSError):
            # We cant open the memory, just return an empty address space.
            pass

    def read(self, addr, length):
        if length > self.session.GetParameter("buffer_size"):
            raise IOError("Too much data to read.")

        self.process_handle.seek(addr)
        try:
            return self.process_handle.read(length)
        except IOError:
            return addrspace.ZEROER.GetZeros(length)

    def __str__(self):
        return "%s(%s)" % (self.__class__.__name__, self.pid)


# Register the process AS as a Linux one.
common.IRProcessAddressSpace = LinuxAPIProcessAddressSpace


class MapModule(address_resolver.Module):
    """A module representing a memory mapping."""


class LinuxAPIAddressResolver(address_resolver.AddressResolverMixin,
                              common.AbstractAPICommandPlugin):
    """A Linux specific address resolver plugin."""

    @staticmethod
    def NormalizeModuleName(module_name):
        if not module_name:
            return ""

        return os.path.basename(module_name)

    def _EnsureInitialized(self):
        if self._initialized:
            return

        task = self.session.GetParameter("process_context")

        for row in self.session.plugins.maps(pids=task.pid):
            maps = row.get("Map")
            if not maps:
                continue

            self.AddModule(MapModule(
                name=(self.NormalizeModuleName(maps.filename) or
                      "map_%#x" % maps.start),
                start=maps.start, end=maps.end, session=self.session))

        self._initialized = True
