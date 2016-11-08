---
abstract: "Scan for possible _KDDEBUGGER_DATA64 structures.\n\n    The scanner is\
  \ detailed here:\n    http://moyix.blogspot.com/2008/04/finding-kernel-global-variables-in.html\n\
  \n    The relevant structures are detailed here:\n    http://doxygen.reactos.org/d3/ddf/include_2psdk_2wdbgexts_8h_source.html\n\
  \n    We can see that _KDDEBUGGER_DATA64.Header is:\n\n    typedef struct _DBGKD_DEBUG_DATA_HEADER64\
  \ {\n        LIST_ENTRY64    List;\n        ULONG           OwnerTag;\n        ULONG\
  \           Size;\n    }\n\n    We essentially search for an owner tag of \"KDBG\"\
  , then overlay the\n    _KDDEBUGGER_DATA64 struct on it. We test for validity by\
  \ reflecting\n    through the Header.List member.\n    "
args: {full_scan: 'Scan the full address space. (type: Boolean)

    ', verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: KDBGScan
epydoc: rekall.plugins.windows.kdbgscan.KDBGScan-class.html
layout: plugin
module: rekall.plugins.windows.kdbgscan
title: kdbgscan
---

Windows keeps a store of some useful global variables in a structure called
**_KDDEBUGGER_DATA64**. This information is used by the microsoft kernel
debugger in order to bootstap the analysis of a crash dump.

Rekall no longer uses the Kernel Debugger Block for analysis - instead accurate
global symbol information are fetched from Microsoft PDB files containing
debugging symbols.

### Notes

1. Previous versions of Rekall used the KDBG heavily for analysis, and by
   extension used this plugin. Currently the KDBG is not used by Rekall at all
   so this plugin is not all that useful.