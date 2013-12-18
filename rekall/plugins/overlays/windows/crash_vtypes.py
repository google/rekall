crash_vtypes = {
## These types are for crash dumps
  '_DMP_HEADER' : [ 0x1000, {
    'Signature' : [ 0x0, ['array', 4, ['unsigned char']]],
    'ValidDump' : [ 0x4, ['array', 4, ['unsigned char']]],
    'MajorVersion' : [ 0x8, ['unsigned long']],
    'MinorVersion' : [ 0xc, ['unsigned long']],
    'DirectoryTableBase' : [ 0x10, ['unsigned long']],
    'PfnDataBase' : [ 0x14, ['unsigned long']],
    'PsLoadedModuleList' : [ 0x18, ['unsigned long']],
    'PsActiveProcessHead' : [ 0x1c, ['unsigned long']],
    'MachineImageType' : [ 0x20, ['unsigned long']],
    'NumberProcessors' : [ 0x24, ['unsigned long']],
    'BugCheckCode' : [ 0x28, ['unsigned long']],
    'BugCheckCodeParameter' : [ 0x2c, ['array', 4, ['unsigned long']]],
    'VersionUser' : [ 0x3c, ['array', 32, ['unsigned char']]],
    'PaeEnabled' : [ 0x5c, ['unsigned char']],
    'KdSecondaryVersion' : [ 0x5d, ['unsigned char']],
    'VersionUser2' : [ 0x5e, ['array', 2, ['unsigned char']]],
    'KdDebuggerDataBlock' : [ 0x60, ['unsigned long']],
    'PhysicalMemoryBlockBuffer' : [ 0x64, ['_PHYSICAL_MEMORY_DESCRIPTOR']],
    'ContextRecord' : [ 0x320, ['array', 1200, ['unsigned char']]],
    'Exception' : [ 0x7d0, ['_EXCEPTION_RECORD32']],
    'Comment' : [ 0x820, ['array', 128, ['unsigned char']]],
    'DumpType' : [ 0xf88, ['unsigned long']],
    'MiniDumpFields' : [ 0xf8c, ['unsigned long']],
    'SecondaryDataState' : [ 0xf90, ['unsigned long']],
    'ProductType' : [ 0xf94, ['unsigned long']],
    'SuiteMask' : [ 0xf98, ['unsigned long']],
    'WriterStatus' : [ 0xf9c, ['unsigned long']],
    'RequiredDumpSpace' : [ 0xfa0, ['unsigned long long']],
    'SystemUpTime' : [ 0xfb8, ['unsigned long long']],
    'SystemTime' : [ 0xfc0, ['unsigned long long']],
    'reserved3' : [ 0xfc8, ['array', 56, ['unsigned char']]],
} ],

  '_PHYSICAL_MEMORY_DESCRIPTOR' : [ 0x10, {
    'NumberOfRuns' : [ 0x0, ['unsigned long']],
    'NumberOfPages' : [ 0x4, ['unsigned long']],
    'Run' : [ 0x8, ['array', 1, ['_PHYSICAL_MEMORY_RUN']]],
} ],
  '_PHYSICAL_MEMORY_RUN' : [ 0x8, {
    'BasePage' : [ 0x0, ['unsigned long']],
    'PageCount' : [ 0x4, ['unsigned long']],
} ],

  '_EXCEPTION_RECORD32' : [ 0x50, {
    'ExceptionCode' : [ 0x0, ['long']],
    'ExceptionFlags' : [ 0x4, ['unsigned long']],
    'ExceptionRecord' : [ 0x8, ['unsigned long']],
    'ExceptionAddress' : [ 0xc, ['unsigned long']],
    'NumberParameters' : [ 0x10, ['unsigned long']],
    'ExceptionInformation' : [ 0x14, ['array', 15, ['unsigned long']]],
} ],

}


crash_64_vtypes = {
  '_DMP_HEADER64' : [ 0x2000, {
    'Signature' : [ 0x0, ['array', 4, ['unsigned char']]],
    'ValidDump' : [ 0x4, ['array', 4, ['unsigned char']]],
    'MajorVersion' : [ 0x8, ['unsigned long']],
    'MinorVersion' : [ 0xc, ['unsigned long']],
    'DirectoryTableBase' : [ 0x10, ['unsigned long long']],
    'PfnDataBase' : [ 0x18, ['unsigned long long']],
    'PsLoadedModuleList' : [ 0x20, ['unsigned long long']],
    'PsActiveProcessHead' : [ 0x28, ['unsigned long long']],
    'MachineImageType' : [ 0x30, ['unsigned long']],
    'NumberProcessors' : [ 0x34, ['unsigned long']],
    'BugCheckCode' : [ 0x38, ['unsigned long']],
    'BugCheckCodeParameter' : [ 0x40, ['array', 4, ['unsigned long long']]],
    'KdDebuggerDataBlock' : [0x80, ['unsigned long long']],
    'PhysicalMemoryBlockBuffer' : [ 0x88, ['_PHYSICAL_MEMORY_DESCRIPTOR']],
    'ContextRecord' : [ 0x348, ['array', 3000, ['unsigned char']]],
    'Exception' : [ 0xf00, ['_EXCEPTION_RECORD64']],
    'DumpType' : [ 0xf98, ['unsigned long']],
    'RequiredDumpSpace' : [ 0xfa0, ['unsigned long long']],
    'SystemTime' : [ 0xfa8, ['unsigned long long']],
    'Comment' : [ 0xfb0, ['array', 128, ['unsigned char']]],
    'SystemUpTime' : [ 0x1030, ['unsigned long long']],
    'MiniDumpFields' : [ 0x1038, ['unsigned long']],
    'SecondaryDataState' : [ 0x103c, ['unsigned long']],
    'ProductType' : [ 0x1040, ['unsigned long']],
    'SuiteMask' : [ 0x1044, ['unsigned long']],
    'WriterStatus' : [ 0x1048, ['unsigned long']],
    'Unused1' : [ 0x104c, ['unsigned char']],
    'KdSecondaryVersion' : [ 0x104d, ['unsigned char']],
    'Unused' : [ 0x104e, ['array', 2, ['unsigned char']]],
    '_reserved0' : [ 0x1050, ['array', 4016, ['unsigned char']]],
} ],

  '_PHYSICAL_MEMORY_DESCRIPTOR' : [ 0x20, {
    'NumberOfRuns' : [ 0x0, ['unsigned long']],
    'NumberOfPages' : [ 0x8, ['unsigned long long']],
    'Run' : [ 0x10, ['array', 1, ['_PHYSICAL_MEMORY_RUN']]],
    }],

  '_PHYSICAL_MEMORY_RUN' : [ 0x10, {
    'BasePage' : [ 0x0, ['unsigned long long']],
    'PageCount' : [ 0x8, ['unsigned long long']],
} ],

  '_EXCEPTION_RECORD64' : [ 0x98, {
    'ExceptionCode' : [ 0x0, ['long']],
    'ExceptionFlags' : [ 0x4, ['unsigned long']],
    'ExceptionRecord' : [ 0x8, ['unsigned long long']],
    'ExceptionAddress' : [ 0x10, ['unsigned long long']],
    'NumberParameters' : [ 0x18, ['unsigned long']],
    '__unusedAlignment' : [ 0x1c, ['unsigned long']],
    'ExceptionInformation' : [ 0x20, ['array', 15, ['unsigned long long']]],
} ],

}
