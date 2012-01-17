
#ifndef _KE_H_
#define _KE_H_

#include "kd.h"

#define MAXIMUM_PROC_PER_SYSTEM 32

//
// Functions
//
UCHAR
xxxKeQueryActiveProcessorCount(
);

USHORT
KeQueryProcessorArchitecture(
);

VOID
KeSaveStateForHibernate(
    OUT PKPROCESSOR_STATE32 ProcState
);

VOID
xxxKiSaveProcessorControlState(
    OUT PKPROCESSOR_STATE32 ProcState
);

VOID
xxxRtlCaptureContext(
    OUT PCONTEXT Context
);

VOID
FASTCALL
KeDisableInterrupts(
);

VOID
FASTCALL
KeRestoreInterrupts(
);

VOID
FASTCALL
KiFlushSingleTb(
    IN PVOID Va
);
#endif
