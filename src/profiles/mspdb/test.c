/***************************************************************
Test program for generating symbols for parsing MS PDB files.
****************************************************************/

#include <stdint.h>

// Some typedefs to make gcc feel like a windows box.
typedef uint32_t DWORD;
typedef uint16_t WORD;
typedef uint16_t SHORT;
typedef uint32_t LONG;
typedef unsigned char BYTE;
typedef int BOOLEAN;
typedef int BOOL;
typedef void * PVOID;
typedef BYTE * PBYTE;
typedef WORD * PWORD;
typedef DWORD * PDWORD;
typedef BOOL * PBOOL;

#define WINAPI

typedef struct _GUID {
  char pad[0x10];
} GUID;

#define MAX_PATH 255

// These files are taken from http://undocumented.rawol.com/win_pdbx.zip
#include "pdb_info.h"
#include "sbs_pdb.h"

int main() {
  lfArray a1;
  lfBitfield a2;
  lfClass a3;
  lfStructure a4;
  lfUnion a5;
  lfEnum a6;
  lfPointer a7;
  lfProc a8;
  lfMFunc a9;
  lfArgList aa;
  lfVTShape ab;
  lfEnumerate ac;
  lfMember ad;
  lfBClass ae;
  lfVFuncTab af;
  lfOneMethod ag;
  lfMethod ah;
  lfNestType ai;
  lfSubRecord b1;
  lfFieldList b2;
  lfRecord b3;

  TYPE_ENUM_e xa1;
  LEAF_ENUM_e xa2;
  SYM_ENUM_e xa3;
  CV_call_e xa4;
  CV_ptrtype_e xb1;
  CV_ptrmode_e xb2;
  CV_access_e xb3;
  CV_methodprop_e xb4;
  PDBStream70 xb5;

  PDB_STREAM_200 c1;
  PDB_HEADER_200 c2;
  PDB_ROOT_200 c3;
  PDB_HEADER_700 c4;
  PDB_ROOT_700 c5;
  PDB_VERSION c6;
  PDB_HEADER c7;
  PDB_ROOT c8;
  PDB_FILE c9;

  HDR d1;
};
