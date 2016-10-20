import weakref
import win32con

import ctypes
from ctypes import wintypes
from rekall import addrspace
from rekall import utils
from rekall.plugins.overlays import basic
from rekall.plugins.response import common
from rekall.plugins.response import processes


READ_ACCESS = (win32con.PROCESS_VM_READ |
               win32con.PROCESS_VM_OPERATION |
               win32con.PROCESS_QUERY_INFORMATION)

MEMORY_PROTECTIONS = {
    0x10: "x---",
    0x20: "xr--",
    0x40: "xrw-",
    0x80: "xrwc",
    0x01: "----",
    0x02: "-r--",
    0x04: "-rw-",
    0x08: "--wc"
}

MEMORY_TYPES = {
    0x1000000: "MEM_IMAGE",
    0x40000: "MEM_MAPPED",
    0x20000: "MEM_PRIVATE"
}

class SYSTEM_INFO_32(ctypes.Structure):
    _fields_ = [("wProcessorArchitecture", wintypes.WORD),
                ("wReserved", wintypes.WORD),
                ("dwPageSize", wintypes.DWORD),
                ("lpMinimumApplicationAddress", wintypes.DWORD),
                ("lpMaximumApplicationAddress", wintypes.DWORD),
                ("dwActiveProcessorMask", wintypes.DWORD),
                ("dwNumberOfProcessors", wintypes.DWORD),
                ("dwProcessorType", wintypes.DWORD),
                ("dwAllocationGranularity", wintypes.DWORD),
                ("wProcessorLevel", wintypes.WORD),
                ("wProcessorRevision", wintypes.WORD)]

class SYSTEM_INFO_64(ctypes.Structure):
    _fields_ = [("wProcessorArchitecture", wintypes.WORD),
                ("wReserved", wintypes.WORD),
                ("dwPageSize", wintypes.DWORD),
                ("lpMinimumApplicationAddress", wintypes.LARGE_INTEGER),
                ("lpMaximumApplicationAddress", wintypes.LARGE_INTEGER),
                ("dwActiveProcessorMask", wintypes.LARGE_INTEGER),
                ("dwNumberOfProcessors", wintypes.DWORD),
                ("dwProcessorType", wintypes.DWORD),
                ("dwAllocationGranularity", wintypes.DWORD),
                ("wProcessorLevel", wintypes.WORD),
                ("wProcessorRevision", wintypes.WORD)]


class MEMORY_BASIC_INFORMATION_32(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", wintypes.DWORD),
        ("AllocationBase", wintypes.DWORD),
	("AllocationProtect", wintypes.DWORD),
	("RegionSize", wintypes.UINT),
	("State", wintypes.DWORD),
	("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD)
    ]


class MEMORY_BASIC_INFORMATION_64(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", wintypes.LARGE_INTEGER),
        ("AllocationBase", wintypes.LARGE_INTEGER),
	("AllocationProtect", wintypes.DWORD),
	("RegionSize", wintypes.LARGE_INTEGER),
	("State", wintypes.DWORD),
	("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD)
    ]

OpenProcess = ctypes.windll.kernel32.OpenProcess
ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [wintypes.HANDLE,
                              wintypes.LPCVOID,
                              wintypes.LPVOID,
                              ctypes.c_size_t,
                              ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = wintypes.BOOL

CloseHandle = ctypes.windll.kernel32.CloseHandle


GetMappedFileNameA = ctypes.windll.psapi.GetMappedFileNameA
GetMappedFileNameA.argtypes = [wintypes.HANDLE,
                               wintypes.LPVOID,
                               wintypes.LPSTR,
                               wintypes.DWORD]
GetMappedFileNameA.restype = wintypes.DWORD

VirtualQueryEx = ctypes.windll.kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [wintypes.HANDLE,
                           wintypes.LPCVOID,
                           wintypes.LPVOID,
                           wintypes.DWORD]
VirtualQueryEx.restype = wintypes.DWORD

MAX_PATH = 1024


class ProcessHandle(object):
    def __init__(self, pid):
        handle = self.handle = ctypes.windll.kernel32.OpenProcess(
            READ_ACCESS, # win32con.PROCESS_ALL_ACCESS,
            False,
            pid)

        # Close the handle on GC so we do not leak handles.
        self._closer = weakref.ref(self, lambda x: CloseHandle(handle))


class LiveVad(utils.AttributeDict):
    """Collect information about a VAD region.

    This is the Live equivalent of _MMVAD.
    """

    @utils.safe_property
    def length(self):
        return self.end - self.start


class APIVad(processes.APIProcessFilter):
    """A VAD plugin using the APIs."""

    name = "vad"

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
        dict(name='VAD', hidden=True),
        dict(name='start', style="address"),
        dict(name='end', style="address"),
        dict(name='Protect', width=4),
        dict(name='filename')
    ]

    def generate_vads(self, pid):
        process_handle = ProcessHandle(pid)

        if not process_handle.handle:
            return

        SYSTEM_INFO = SYSTEM_INFO_64
        MEMORY_BASIC_INFORMATION = MEMORY_BASIC_INFORMATION_64

        system_info = SYSTEM_INFO()
        psystem_info = ctypes.byref(system_info)
        ctypes.windll.kernel32.GetSystemInfo(psystem_info)

        base_address = system_info.lpMinimumApplicationAddress
        max_address = system_info.lpMaximumApplicationAddress
        page_address = base_address

        while page_address < max_address:
            mbi = MEMORY_BASIC_INFORMATION()
            mbi_pointer = ctypes.byref(mbi)
            size = ctypes.sizeof(mbi)
            success = VirtualQueryEx(
                process_handle.handle,
                page_address,
                mbi_pointer,
                size)

            if not success:
                break

            if mbi.AllocationProtect != 0:
                # Try to resolve the filename if possible.
                filename = ctypes.create_string_buffer("", MAX_PATH)
                copied = GetMappedFileNameA(
                    process_handle.handle, page_address, filename, MAX_PATH)
                if copied > 0:
                    filename = filename.value
                else:
                    filename = None

                yield LiveVad(
                    start=mbi.BaseAddress,
                    end=mbi.BaseAddress + mbi.RegionSize,
                    protection=mbi.AllocationProtect,
                    current_protection=mbi.Protect,
                    type=MEMORY_TYPES.get(mbi.Type, mbi.Type),
                    filename=filename,
                    pid=pid
                )

            page_address = mbi.BaseAddress + mbi.RegionSize

    def merge_ranges(self, pid):
        """Generate merged ranges."""
        old_vad = None

        for vad in self.generate_vads(pid):
            # Try to merge this range with the previous range.
            if (old_vad and
                old_vad.end == vad.start and
                old_vad.protection == vad.protection and
                old_vad.filename == vad.filename):
                old_vad.end = vad.end
                continue

            # Yield the old range:
            if old_vad:
                yield old_vad

            old_vad = vad

        # Emit the last range.
        if old_vad:
            yield old_vad

    def collect(self):
        generator = self.generate_vads
        if self.plugin_args.verbosity <= 1:
            generator = self.merge_ranges

        for proc in self.filter_processes():
            divider = "{0} pid: {1:6}\n".format(proc.name, proc.pid)
            yield dict(divider=divider)

            for vad in generator(proc.pid):
                if (self.plugin_args.regex and not
                    self.plugin_args.regex.search(vad.filename or "")):
                    continue

                if (self.plugin_args.offset is not None and
                    not vad.start <= self.plugin_args.offset <= vad.end):
                    continue

                yield dict(proc=proc,
                           VAD=vad,
                           start=vad.start,
                           end=vad.end,
                           Protect=MEMORY_PROTECTIONS.get(
                               vad.protection),
                           filename=vad.filename)


class WinAPIProcessAddressSpace(addrspace.RunBasedAddressSpace):
    """An address space which read processes using ReadProcessMemory()."""

    def __init__(self, pid=None, **kwargs):
        super(WinAPIProcessAddressSpace, self).__init__(**kwargs)

        self.process_handle = ProcessHandle(pid)
        for vad in self.session.plugins.vad().merge_ranges(pid):
            self.add_run(vad.start, vad.start, vad.length,
                         address_space=self, data=dict(pid=pid, vad=vad))

    def read(self, addr, length):
        if length > self.session.GetParameter("buffer_size"):
            raise IOError("Too much data to read.")

        result = ctypes.create_string_buffer(length)
        bytes_read = ctypes.c_size_t()
        status = ReadProcessMemory(
            self.process_handle.handle,
            addr, result, length, ctypes.byref(bytes_read))

        # Failed ... return zeros.
        if status == 0:
            return addrspace.ZEROER.GetZeros(length)

        return result.raw

# Register the process AS as a windows one.
common.APIProcessAddressSpace = WinAPIProcessAddressSpace


def is_wow64(proc):
    """Determine if the proc is Wow64."""
    # Not the most accurate method but very fast.
    return (proc.environ.get("PROCESSOR_ARCHITECTURE") == 'x86' and
            proc.environ.get("PROCESSOR_ARCHITEW6432") == 'AMD64')


class WinAPIProfile(common.APIBaseProfile):
    """Profile for Windows live analysis."""

    def __init__(self, proc=None, **kwargs):
        super(WinAPIProfile, self).__init__(**kwargs)

        # This is a profile for a dll or module in the current process
        # context. Depending if the current process is a Wow64 process we need
        # to load the 32 or 64 bit profiles.
        process_context = proc or self.session.GetParameter("process_context")
        if process_context:
            if is_wow64(process_context):
                basic.Profile32Bits.Initialize(self)
            else:
                basic.ProfileLLP64.Initialize(self)


# Register the profile for windows.
common.APIProfile = WinAPIProfile
