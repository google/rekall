#ifndef _ZWDDK_H
#define _ZWDDK_H

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemUnused1,
    SystemPerformanceTraceInformation,
    SystemCrashDumpInformation,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemUnused3,
    SystemUnused4,
    SystemUnused5,
    SystemUnused6,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation,
    SystemTimeSlipNotification,
    SystemSessionCreate,
    SystemSessionDetach,
    SystemSessionInformation

} SYSTEM_INFORMATION_CLASS;

//
// SystemProcessorInformation
//
typedef struct _SYSTEM_PROCESSOR_INFORMATION {
    USHORT KeProcessorArchitecture;
    USHORT KeProcessorLevel;
    USHORT KeProcessorRevision;
    USHORT AlwaysZero;
    ULONG KeFeatureBits;
} SYSTEM_PROCESSOR_INFORMATION, *PSYSTEM_PROCESSOR_INFORMATION;

//
// SystemBasicInformation
//
typedef struct _SYSTEM_BASIC_INFORMATION
{
 ULONG Reserved;
 ULONG TimerResolution;
 ULONG PhysicalPageSize;
 ULONG NumberOfPhysicalPages;
 ULONG LowestPhysicalPage;
 ULONG HighestPhysicalPage;
 ULONG AllocationGranularity;
 ULONG MinimumUserModeAddress;
 ULONG MaximumUserModeAddress;
 ULONG ActiveProcessors;
 UCHAR NumberProcessors;
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation (
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

#endif