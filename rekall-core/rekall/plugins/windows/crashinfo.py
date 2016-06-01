# Rekall Memory Forensics
#
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Authors:
# Michael Cohen <scudette@gmail.com>
# Based on code by Aaron Walters.
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

# pylint: disable=protected-access

from rekall import plugin
from rekall import testlib
from rekall.plugins.windows import common
from rekall.plugins.addrspaces import crash
from rekall.plugins.addrspaces import standard
from rekall.plugins.overlays.windows import crashdump


class WritableCrashDump(crash.WindowsCrashDumpSpace64,
                        standard.WritableAddressSpace):
    """A writable crash dump address space.

    When creating a new crash dump, we need to moodify the image:
    1) To rebuild the KDBG block.
    2) To decrypt the KDBG block in images which obfuscate it.
    """


class Raw2Dump(common.WindowsCommandPlugin):
    """Convert the physical address space to a crash dump.

    The Windows debugger (Windbg) works only with memory dumps stored
    in the proprietary 'crashdump' file format. This file format
    contains the following features:

    1) Physical memory ranges are stored in a sparse way - there is a
       'Runs' table which specifies the mapping between the physical
       offset and the file offset of each page. This allows the format
       to omit unmapped regions (unlike raw format which must pad them
       with zero to maintain alignment).

    2) The crash dump header contains metadata about the
       image. Specifically, the header contain a copy of the Kernel
       Debugger Data Block (AKA the KDBG). This data is used to
       bootstrap the windows debugger by providing critical initial
       hints to the debugger.

    Since the KDBG block is created at system boot and never used
    (until the crash dump is written) it is trivial for malware to
    overwrite it - making it really hard for responders since windbg
    will not be able to read the file. In later versions of windows,
    the kdbg is also obfuscated (See the function "nt!KdCopyDataBlock"
    which decrypts it.).

    Rekall itself does not use the KDBG block any more, although older
    memory forensic tools still do use it. Rekall instead relies on
    accurate debugging symbols to locate critical kernel data
    structures, reducing the level of trust we place on the image
    itself (so Rekall is more resilient to manipulation).

    In order to ensure that the windows debugger is able to read the
    produced crash dump, we recreate the kernel debugger block from
    the symbol information we already have.

    NOTE: The crashdump file format can be deduced by:

    dis 'nt!IoFillDumpHeader'

    This is the reference for this plugin.
    """

    __name = "raw2dmp"

    @classmethod
    def args(cls, parser):
        super(Raw2Dump, cls).args(parser)
        parser.add_argument(
            "--destination", default=None,
            help="The destination path to write the crash dump.")

        parser.add_argument(
            "--rebuild", default=False, type="Boolean",
            help="Rebuild the KDBG data block.")

    def __init__(self, destination=None, rebuild=False, **kwargs):
        super(Raw2Dump, self).__init__(**kwargs)
        if self.session.profile.metadata("arch") == "I386":
            self.profile = crashdump.CrashDump32Profile.Initialize(
                self.profile.copy())
        elif self.session.profile.metadata("arch") == "AMD64":
            self.profile = crashdump.CrashDump64Profile.Initialize(
                self.profile.copy())
        else:
            raise plugin.PluginError(
                "Unable to write crashdump for this architecture.")

        self.buffer_size = 10 * 1024 * 1024
        self.rebuild = rebuild
        self.destination = destination
        if not destination:
            raise plugin.PluginError(
                "A destination filename must be provided.")

    def _pointer_to_int(self, ptr):
        if self.profile.metadata("arch") == "I386":
            return ptr

        return ptr | 0xFFFFF00000000000

    def _SetKDBG(self, kdbg, member, symbol=None):
        if symbol is None:
            symbol = "nt!%s" % member

        symbol = self.session.address_resolver.get_address_by_name(symbol)

        # If the symbol does not exist in the profile, we ignore it here.
        if symbol == None:
            return

        kdbg.SetMember(member, self._pointer_to_int(symbol))

    def RebuildKDBG(self, out_fd):
        """Modify the destination image to rebuild the KDBG."""
        if self.profile.metadata("arch") == "I386":
            crash_as_cls = crash.WindowsCrashDumpSpace32
        else:
            crash_as_cls = crash.WindowsCrashDumpSpace64

        # Open the crash file for writing.
        crash_as = crash_as_cls(base=out_fd, session=self.session)

        kdbg_virtual_address = self.session.GetParameter("kdbg")
        kdbg_physical_address = self.kernel_address_space.vtop(
            kdbg_virtual_address)

        # Construct a _KDDEBUGGER_DATA64 over the old one.
        kdbg = self.profile._KDDEBUGGER_DATA64(
            offset=kdbg_physical_address,
            vm=crash_as)

        # Clear the old data just in case.
        crash_as.write(kdbg_physical_address, "\x00" * kdbg.obj_size)

        # The KDBG header.
        kdbg.Header.OwnerTag = "KDBG"
        kdbg.Header.Size = kdbg.obj_size
        kdbg.Header.List.Flink = kdbg.Header.List.Blink = (
            self._pointer_to_int(kdbg_virtual_address))

        kdbg.MmPageSize = 0x1000

        # _KTHREAD offsets.
        kthread = self.profile._KTHREAD()
        ethread = self.profile._ETHREAD()
        kdbg.SizeEThread = ethread.obj_size
        kdbg.OffsetKThreadNextProcessor = kthread.NextProcessor.obj_offset

        kdbg.OffsetKThreadTeb = kthread.Teb.obj_offset
        kdbg.OffsetKThreadKernelStack = kthread.KernelStack.obj_offset
        kdbg.OffsetKThreadInitialStack = kthread.InitialStack.obj_offset

        kdbg.OffsetKThreadState = kthread.State.obj_offset
        kdbg.OffsetKThreadApcProcess = kthread.ApcState.Process.obj_offset

        # _EPROCESS offsets.
        eprocess = self.profile._EPROCESS()
        kdbg.SizeEProcess = eprocess.obj_size
        kdbg.OffsetEprocessPeb = eprocess.m("Peb").obj_offset
        kdbg.OffsetEprocessParentCID = (
            eprocess.InheritedFromUniqueProcessId.obj_offset)
        kdbg.OffsetEprocessDirectoryTableBase = (
            eprocess.Pcb.DirectoryTableBase.obj_offset)

        # _KPRCB offsets.
        prcb = self.profile._KPRCB()
        kdbg.SizePrcb = prcb.obj_size
        kdbg.OffsetPrcbDpcRoutine = prcb.DpcRoutineActive.obj_offset
        kdbg.OffsetPrcbCurrentThread = prcb.CurrentThread.obj_offset
        kdbg.OffsetPrcbMhz = prcb.MHz.obj_offset
        kdbg.OffsetPrcbCpuType = prcb.CpuType.obj_offset
        kdbg.OffsetPrcbVendorString = prcb.VendorString.obj_offset
        kdbg.OffsetPrcbProcStateSpecialReg = (
            prcb.ProcessorState.SpecialRegisters.obj_offset)

        kdbg.OffsetPrcbProcStateContext = (
            prcb.ProcessorState.ContextFrame.obj_offset)

        kdbg.OffsetPrcbNumber = prcb.Number.obj_offset

        # _KPCR offsets.
        pcr = self.profile._KPCR()
        kdbg.SizePcr = pcr.obj_size

        if self.profile.metadata("arch") == "AMD64":
            kdbg.OffsetPrcbContext = prcb.Context.obj_offset
            kdbg.OffsetPcrSelfPcr = pcr.Self.obj_offset
            kdbg.OffsetPcrCurrentPrcb = pcr.CurrentPrcb.obj_offset
            kdbg.OffsetPcrContainedPrcb = pcr.Prcb.obj_offset

            # Clear the KdpDataBlockEncoded flag from the image.
            flag = self.profile.get_constant_object(
                "KdpDataBlockEncoded", "byte")

            crash_as.write(
                self.kernel_address_space.vtop(flag.obj_offset), "\x01")

        # Global constants.
        self._SetKDBG(kdbg, "CmNtCSDVersion")
        self._SetKDBG(kdbg, "ExpNumberOfPagedPools")
        self._SetKDBG(kdbg, "ExpPagedPoolDescriptor")
        self._SetKDBG(kdbg, "ExpPagedPoolDescriptor")
        self._SetKDBG(kdbg, "ExpSystemResourcesList")
        self._SetKDBG(kdbg, "KdPrintBufferSize")
        self._SetKDBG(kdbg, "KdPrintCircularBuffer")
        self._SetKDBG(kdbg, "KdPrintCircularBufferEnd", "nt!KdpBreakpointTable")
        self._SetKDBG(kdbg, "KdPrintRolloverCount")
        self._SetKDBG(kdbg, "KdPrintWritePointer")
        self._SetKDBG(kdbg, "KeLoaderBlock", "nt!KdpLoaderDebuggerBlock")
        self._SetKDBG(kdbg, "KeTimeIncrement")
        self._SetKDBG(kdbg, "KernBase", "nt")
        self._SetKDBG(kdbg, "KiBugCheckData")
        self._SetKDBG(kdbg, "KiCallUserMode")
        self._SetKDBG(kdbg, "KiProcessorBlock")
        self._SetKDBG(kdbg, "KiProcessorBlock")
        self._SetKDBG(kdbg, "MmAvailablePages")
        self._SetKDBG(kdbg, "MmFreePageListHead")
        self._SetKDBG(kdbg, "MmHighestPhysicalPage")
        self._SetKDBG(kdbg, "MmHighestUserAddress")
        self._SetKDBG(kdbg, "MmLastUnloadedDriver")
        self._SetKDBG(kdbg, "MmLoadedUserImageList")
        self._SetKDBG(kdbg, "MmLowestPhysicalPage")
        self._SetKDBG(kdbg, "MmMaximumNonPagedPoolInBytes")
        self._SetKDBG(kdbg, "MmModifiedNoWritePageListHead")
        self._SetKDBG(kdbg, "MmModifiedPageListHead")
        self._SetKDBG(kdbg, "MmNonPagedPoolStart")
        self._SetKDBG(kdbg, "MmNumberOfPagingFiles")
        self._SetKDBG(kdbg, "MmNumberOfPhysicalPages")
        self._SetKDBG(kdbg, "MmPagedPoolEnd")
        self._SetKDBG(kdbg, "MmPagedPoolInformation", "nt!MmPagedPoolInfo")
        self._SetKDBG(kdbg, "MmPfnDatabase")
        self._SetKDBG(kdbg, "MmPhysicalMemoryBlock")
        self._SetKDBG(kdbg, "MmResidentAvailablePages")
        self._SetKDBG(kdbg, "MmSizeOfPagedPoolInBytes")
        self._SetKDBG(kdbg, "MmStandbyPageListHead")
        self._SetKDBG(kdbg, "MmSubsectionBase")
        self._SetKDBG(kdbg, "MmSystemCacheWs")
        self._SetKDBG(kdbg, "MmSystemRangeStart")
        self._SetKDBG(kdbg, "MmUnloadedDrivers")
        self._SetKDBG(kdbg, "MmUserProbeAddress")
        self._SetKDBG(kdbg, "MmZeroedPageListHead")
        self._SetKDBG(kdbg, "NonPagedPoolDescriptor")
        self._SetKDBG(kdbg, "NtBuildLab")
        self._SetKDBG(kdbg, "ObpRootDirectoryObject")
        self._SetKDBG(kdbg, "ObpTypeObjectType")
        self._SetKDBG(kdbg, "PoolTrackTable")
        self._SetKDBG(kdbg, "PsActiveProcessHead")
        self._SetKDBG(kdbg, "PsLoadedModuleList")
        self._SetKDBG(kdbg, "PspCidTable")

    def render(self, renderer):
        PAGE_SIZE = 0x1000

        # We write the image to the destination using the WritableAddressSpace.
        out_as = standard.WritableAddressSpace(
            filename=self.destination, session=self.session,
            mode="w+b")

        # Pad the header area with PAGE pattern:
        if self.profile.metadata("arch") == "AMD64":
            header = self.profile._DMP_HEADER64(vm=out_as)
            out_as.write(0, "PAGE" * (header.obj_size / 4))
            out_as.write(4, "DU64")
        else:
            # 32 bit systems use a smaller structure.
            header = self.profile._DMP_HEADER(vm=out_as)
            out_as.write(0, "PAGE" * (header.obj_size / 4))
            out_as.write(4, "DUMP")

            # PEA address spaces.
            if getattr(self.kernel_address_space, "pae", None):
                header.PaeEnabled = 1

        # Write the runs from our physical address space.
        number_of_pages = 0
        i = None

        for i, run in enumerate(self.physical_address_space.get_mappings()):
            # Convert to pages
            start = run.start / PAGE_SIZE
            length = run.length / PAGE_SIZE

            header.PhysicalMemoryBlockBuffer.Run[i].BasePage = start
            header.PhysicalMemoryBlockBuffer.Run[i].PageCount = length
            number_of_pages += length

        # There must be at least one run.
        if i is None:
            raise plugin.PluginError(
                "Physical address space has no available data.")

        header.PhysicalMemoryBlockBuffer.NumberOfRuns = i + 1
        header.PhysicalMemoryBlockBuffer.NumberOfPages = number_of_pages

        resolver = self.session.address_resolver

        # Set members of the crash header
        header.MajorVersion = 0xf
        header.MinorVersion = 0x1db1
        header.DirectoryTableBase = self.session.GetParameter("dtb")
        header.PfnDataBase = self._pointer_to_int(
            resolver.get_address_by_name("nt!MmPfnDatabase"))

        header.PsLoadedModuleList = self._pointer_to_int(
            resolver.get_address_by_name("nt!PsLoadedModuleList"))

        header.PsActiveProcessHead = self._pointer_to_int(
            resolver.get_address_by_name("nt!PsActiveProcessHead"))

        header.KdDebuggerDataBlock = self._pointer_to_int(
            resolver.get_address_by_name("nt!KdDebuggerDataBlock"))

        header.MachineImageType = 0x8664

        # Find the number of processors
        header.NumberProcessors = self.profile.get_constant_object(
            "KeNumberProcessors", "unsigned int")

        # Copy some stuff from _KUSER_SHARED_DATA.
        kuser_shared = self.profile.get_constant_object(
            "KI_USER_SHARED_DATA", "_KUSER_SHARED_DATA")
        header.SystemTime = kuser_shared.SystemTime.as_windows_timestamp()
        header.SystemUpTime = (
            kuser_shared.InterruptTime.LowPart +
            kuser_shared.InterruptTime.High1Time << 32) / 100000
        header.ProductType = kuser_shared.NtProductType
        header.SuiteMask = kuser_shared.SuiteMask

        # Zero out the BugCheck members
        header.BugCheckCode = 0x00000000
        header.BugCheckCodeParameter[0] = 0x00000000
        header.BugCheckCodeParameter[1] = 0x00000000
        header.BugCheckCodeParameter[2] = 0x00000000
        header.BugCheckCodeParameter[3] = 0x00000000

        # Set the sample run information
        header.RequiredDumpSpace = number_of_pages + header.obj_size / PAGE_SIZE
        header.DumpType = 1

        # Zero out the remaining non-essential fields from ContextRecordOffset
        # to ExceptionOffset.
        out_as.write(header.ContextRecord.obj_offset,
                     "\x00" * (header.m("Exception").obj_offset -
                               header.ContextRecord.obj_offset))

        # Set the "converted" comment
        out_as.write(header.Comment.obj_offset,
                     "Created with Rekall Memory Forensics\x00")

        # Now copy the physical address space to the output file.
        output_offset = header.obj_size
        for run in self.physical_address_space.get_mappings():
            # Convert to pages
            start = run.start / PAGE_SIZE
            length = run.length / PAGE_SIZE

            renderer.write("\nRun [0x%08X, 0x%08X] \n" % (
                start, length))
            data_length = length * PAGE_SIZE
            start_offset = start * PAGE_SIZE
            offset = 0
            while data_length > 0:
                to_read = min(data_length, self.buffer_size)

                data = self.physical_address_space.read(
                    start_offset + offset, to_read)

                out_as.write(output_offset, data)
                output_offset += len(data)
                offset += len(data)
                data_length -= len(data)
                renderer.RenderProgress(
                    "Wrote %sMB.", (start_offset + offset) / 1024 / 1024)

        # Rebuild the KDBG data block if needed. According to the
        # disassembly of nt!KdCopyDataBlock the data block is
        # encrypted when nt!KdpDataBlockEncoded is non zero:

        # ------ nt!KdCopyDataBlock ------
        # SUB RSP, 0x28
        # CMP BYTE [RIP+0x10fac7], 0x0   0x0 nt!KdpDataBlockEncoded
        # MOV RDX, RCX
        # JZ 0xf8000291e6a7              nt!KdCopyDataBlock + 0x57

        if self.rebuild or self.profile.get_constant_object(
                "KdpDataBlockEncoded", "byte") > 0:
            renderer.format("Rebuilding KDBG data block.\n")
            self.RebuildKDBG(out_as)


class TestRaw2Dump(testlib.HashChecker):
    PARAMETERS = dict(
        commandline="raw2dmp --rebuild --destination %(tempdir)s/output.dmp "
    )
