
---
layout: plugin
title: kdbgscan
abstract: |
    Scan for possible _KDDEBUGGER_DATA64 structures.

    The scanner is detailed here:
    http://moyix.blogspot.com/2008/04/finding-kernel-global-variables-in.html

    The relevant structures are detailed here:
    http://doxygen.reactos.org/d3/ddf/include_2psdk_2wdbgexts_8h_source.html

    We can see that _KDDEBUGGER_DATA64.Header is:

    typedef struct _DBGKD_DEBUG_DATA_HEADER64 {
        LIST_ENTRY64    List;
        ULONG           OwnerTag;
        ULONG           Size;
    }

    We essentially search for an owner tag of "KDBG", then overlay the
    _KDDEBUGGER_DATA64 struct on it. We test for validity by reflecting
    through the Header.List member.
    

epydoc: rekall.plugins.windows.kdbgscan.KDBGScan-class.html
---
