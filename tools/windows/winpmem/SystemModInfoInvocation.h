#ifndef SystemModInfoInvocation_H
#define SystemModInfoInvocation_H

// xxx: this contains my export version data for the ZwQuerySystemInformation invocation XI.

// xxx: please don't remove the #ifndef's.

#ifndef _SYSTEM_INFORMATION_CLASS
#define SystemModuleInformation 11
#endif

#ifndef _SYSTEM_MODULE_INFORMATION_ENTRY
typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY
{
	ULONG reserved1;
	ULONG reserved2;
	#ifdef _WIN64
	ULONG Reserved3;
	ULONG Reserved4;
	#endif
	PVOID Base; // the imagebase address
	ULONG Size; // the total size of the image
	ULONG Flags;
	USHORT Index;
	USHORT NameLength;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	char ImageName[256]; // normal ascii, fixed 256 char array
	
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;
#endif

#ifndef _SYSTEM_MODULE_INFORMATION
typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Count;
	SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;
#endif


#ifndef ZwQuerySystemInformation
NTSYSAPI NTSTATUS NTAPI
ZwQuerySystemInformation(
	__in SIZE_T SystemInformationClass,
	__out PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
);
#endif

#endif