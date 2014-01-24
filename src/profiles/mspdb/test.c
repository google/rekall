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
  unsigned long Data1;
  unsigned short Data2;
  unsigned short Data3;
  char Data4[8];
} GUID;

#define MAX_PATH 255

// These files are taken from http://undocumented.rawol.com/win_pdbx.zip
#include "pdb_info.h"
#include "sbs_pdb.h"

struct IMAGE_SECTION_HEADER {
  char Name[8];
  union {
    uint32_t PhysicalAddress;
    uint32_t VirtualSize;
  } Misc;

  uint32_t VirtualAddress;
  uint32_t SizeOfRawData;
  uint32_t PointerToRawData;
  uint32_t PointerToRelocations;
  uint32_t PointerToLinenumbers;
  uint16_t NumberOfRelocations;
  uint16_t NumberOfLinenumbers;
  uint32_t Characteristics;
} a1;


struct DbgHdr {
  uint16_t snFPO;
  uint16_t snException;
  uint16_t snFixup;
  uint16_t snOmapToSrc;
  uint16_t snOmapFromSrc;
  uint16_t snSectionHdr;
  uint16_t snTokenRidMap;
  uint16_t snXdata;
  uint16_t snPdata;
  uint16_t snNewFPO;
  uint16_t snSectionHdrOrig;
} a2;


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

  /* DBI Stream. */
  HDR d1;
  NewDBIHdr d2;
  OMAP_DATA d3;

  /* Symbols stream. */
  ALIGNSYM e1;
  ANNOTATIONSYM  e2;
  ATTRMANYREGSYM  e3;
  ATTRMANYREGSYM2  e4;
  ATTRREGREL  e5;
  ATTRREGSYM  e6;
  ATTRSLOTSYM  e7;
  BLOCKSYM  e8;
  BLOCKSYM16  e9;
  BLOCKSYM32  eq;
  BPRELSYM16  ew;
  BPRELSYM32  ee;
  CEXMSYM32  er;
  CFLAGSYM   et;
  COMPILESYM  ey;
  CONSTSYM  eu;
  CONSTSYM_16t  ei;
  DATASYM16   eo;
  DATASYM32  ea;
  ENTRYTHISSYM  es;
  FRAMEPROCSYM  ed;
  FRAMERELSYM  ef;
  LABELSYM16  eg;
  LABELSYM32  eh;
  MANPROCSYM  ej;
  MANYREGSYM  ek;
  MANYREGSYM2  el;
  OBJNAMESYM  ez;
  OEMSYMBOL  ex;
  PROCSYM16  ec;
  PROCSYM32  ev;
  PROCSYMIA64  eb;
  PUBSYM32  en;
  REFSYM   f1;
  REFSYM2  f2;
  REGREL32  f3;
  REGSYM f4;
};
