
// sbs_pdb.h
// 06-25-2006 Sven B. Schreiber
// sbs@orgon.com

////////////////////////////////////////////////////////////////////
#ifdef _SBS_PDB_DLL_
////////////////////////////////////////////////////////////////////

// =================================================================
// PROGRAM IDENTIFICATION
// =================================================================

#define MAIN_BUILD              1
#define MAIN_VERSION_HIGH       1
#define MAIN_VERSION_LOW        0

// -----------------------------------------------------------------

#define MAIN_DAY                25
#define MAIN_MONTH              06
#define MAIN_YEAR               2006

// -----------------------------------------------------------------

#define MAIN_PREFIX             SBS
#define MAIN_MODULE             sbs_pdb
#define MAIN_NAME               SBS Program Database Parser
#define MAIN_COMPANY            Sven B. Schreiber
#define MAIN_AUTHOR             Sven B. Schreiber
#define MAIN_EMAIL              sbs@orgon.com
#define MAIN_DLL

////////////////////////////////////////////////////////////////////
#endif // #ifdef _SBS_PDB_DLL_
////////////////////////////////////////////////////////////////////

// =================================================================
// HEADER FILES
// =================================================================

////////////////////////////////////////////////////////////////////
#ifndef _RC_PASS_
////////////////////////////////////////////////////////////////////

// =================================================================
// MORE HEADER FILES
// =================================================================

//#include <sbs_rtl.h>
//#include "pdb_info.h"

// =================================================================
// CONSTANTS
// =================================================================

#define PDB_UNUSED_16       (( WORD) -1) // unused stream (16-bit)
#define PDB_UNUSED_32       ((DWORD) -1) // unused stream (32-bit)

#define PDB_TI_MIN          0x00001000   // type index base
#define PDB_TI_MAX          0x00FFFFFF   // type index limit

// =================================================================
// STREAM IDS
// =================================================================

#define PDB_STREAM_ROOT     0 // PDB root directory
#define PDB_STREAM_PDB      1 // PDB stream info
#define PDB_STREAM_TPI      2 // type info
#define PDB_STREAM_DBI      3 // debug info

// =================================================================
// PDB 2.00 STRUCTURES
// =================================================================

#define PDB_VERSION_200     200    // binary version number
#define PDB_SIGNATURE_200_  0x2C   // signature size (bytes)
#define PDB_SIGNATURE_200 \
        "Microsoft C/C++ program database 2.00\r\n\032JG\0"

// -----------------------------------------------------------------

typedef struct _PDB_STREAM_200
    {
    DWORD dStreamBytes;            // stream size (-1 = unused)
    PVOID pReserved;               // implementation dependent
    }
    PDB_STREAM_200, *PPDB_STREAM_200, **PPPDB_STREAM_200;

#define PDB_STREAM_200_ sizeof (PDB_STREAM_200)

// -----------------------------------------------------------------

typedef struct _PDB_HEADER_200
    {
    BYTE           abSignature [PDB_SIGNATURE_200_]; // version ID
    DWORD          dPageBytes;     // 0x0400, 0x0800, 0x1000
    WORD           wStartPage;     // 0x0009, 0x0005, 0x0002
    WORD           wFilePages;     // file size / dPageBytes
    PDB_STREAM_200 RootStream;     // stream directory
    WORD           awRootPages []; // pages containing PDB_ROOT_200
    }
    PDB_HEADER_200, *PPDB_HEADER_200, **PPPDB_HEADER_200;

#define PDB_HEADER_200_ sizeof (PDB_HEADER_200)

#define PDB_HEADER_200__(_n) \
        (PDB_HEADER_200_ + ((DWORD) (_n) * WORD_))

// -----------------------------------------------------------------

typedef struct _PDB_ROOT_200
    {
    WORD           wStreams;       // number of streams
    WORD           wReserved;      // not used
    PDB_STREAM_200 aStreams [];    // stream size list
    }
    PDB_ROOT_200, *PPDB_ROOT_200, **PPPDB_ROOT_200;

#define PDB_ROOT_200_ sizeof (PDB_ROOT_200)

#define PDB_ROOT_200__(_n) \
        (PDB_ROOT_200_ + ((DWORD) (_n) * PDB_STREAM_200_))

// =================================================================
// PDB 7.00 STRUCTURES
// =================================================================

#define PDB_VERSION_700     700    // binary version number
#define PDB_SIGNATURE_700_  0x20   // signature size (bytes)
#define PDB_SIGNATURE_700 \
        "Microsoft C/C++ MSF 7.00\r\n\032DS\0\0"

// -----------------------------------------------------------------

typedef struct _PDB_HEADER_700
    {
    BYTE  abSignature [PDB_SIGNATURE_700_]; // version ID
    DWORD dPageBytes;              // 0x0400
    DWORD dFlagPage;               // 0x0002
    DWORD dFilePages;              // file size / dPageBytes
    DWORD dRootBytes;              // stream directory size
    DWORD dReserved;               // 0
    DWORD adIndexPages [];         // root page index pages
    }
    PDB_HEADER_700, *PPDB_HEADER_700, **PPPDB_HEADER_700;

#define PDB_HEADER_700_ sizeof (PDB_HEADER_700)

#define PDB_HEADER_700__(_n) \
        (PDB_HEADER_700_ + ((DWORD) (_n) * DWORD_))

// -----------------------------------------------------------------

typedef struct _PDB_ROOT_700
    {
    DWORD dStreams;                // number of streams
    DWORD adStreamBytes [];        // stream size list
    }
    PDB_ROOT_700, *PPDB_ROOT_700, **PPPDB_ROOT_700;

#define PDB_ROOT_700_ sizeof (PDB_ROOT_700)

#define PDB_ROOT_700__(_n) \
        (PDB_ROOT_700_ + ((DWORD) (_n) * DWORD_))

// =================================================================
// VERSION-INDEPENDENT PDB STRUCTURES
// =================================================================

typedef struct _PDB_VERSION
    {
    DWORD dVersion;                // version number
    DWORD dHeader;                 // header size
    PBYTE pbSignature;             // version ID
    }
    PDB_VERSION, *PPDB_VERSION, **PPPDB_VERSION;

#define PDB_VERSION_ sizeof (PDB_VERSION)

// -----------------------------------------------------------------

typedef union _PDB_HEADER
    {
      //    BYTE           abSignature []; // version ID
    PDB_HEADER_200 V200;           // version 2.00 header
    PDB_HEADER_700 V700;           // version 7.00 header
    }
    PDB_HEADER, *PPDB_HEADER, **PPPDB_HEADER;

#define PDB_HEADER_ sizeof (PDB_HEADER)

// -----------------------------------------------------------------

typedef union _PDB_ROOT
    {
    PDB_ROOT_200 V200;             // version 2.00 root directory
    PDB_ROOT_700 V700;             // version 7.00 root directory
    }
    PDB_ROOT, *PPDB_ROOT, **PPPDB_ROOT;

#define PDB_ROOT_ sizeof (PDB_ROOT)

// -----------------------------------------------------------------

typedef struct _PDB_FILE
    {
    WORD        awPath [MAX_PATH]; // fully qualified path
    PPDB_HEADER pHeader;           // header
    PPDB_ROOT   pRoot;             // root directory
    DWORD       dRoot;             // root directory size
    DWORD       dVersion;          // PDB version number
    DWORD       dStreams;          // number of streams
    }
    PDB_FILE, *PPDB_FILE, **PPPDB_FILE;

#define PDB_FILE_ sizeof (PDB_FILE)

// -----------------------------------------------------------------

typedef struct _PDB_STREAM
    {
    PVOID pData;                   // stream data pointer
    DWORD dData;                   // stream size in bytes
    BOOL  fUnused;                 // indicates unused stream
    }
    PDB_STREAM, *PPDB_STREAM, **PPPDB_STREAM;

#define PDB_STREAM_ sizeof (PDB_STREAM)

// -----------------------------------------------------------------

typedef struct _PDB_DATA
    {
    WORD       awPath [MAX_PATH];  // fully qualified path
    DWORD      dVersion;           // PDB version number
    DWORD      dStreams;           // number of streams
    PDB_STREAM aStreams [];
    }
    PDB_DATA, *PPDB_DATA, **PPPDB_DATA;

#define PDB_DATA_ sizeof (PDB_DATA)
#define PDB_DATA__(_n) (PDB_DATA_ + ((DWORD) (_n) * PDB_STREAM_))

// =================================================================
// CONDITIONAL ANSI/UNICODE SYMBOLS
// =================================================================

#ifdef  UNICODE

#define pdbFileHeader   pdbFileHeaderW
#define pdbFileOpen     pdbFileOpenW
#define pdbDataOpen     pdbDataOpenW

#else   // #ifdef UNICODE

#define pdbFileHeader   pdbFileHeaderA
#define pdbFileOpen     pdbFileOpenA
#define pdbDataOpen     pdbDataOpenA

#endif  // #ifdef UNICODE

// =================================================================
// API PROTOTYPES
// =================================================================

DWORD WINAPI pdbFileValid (PPDB_HEADER pph,
                           DWORD       dFileBytes);

PPDB_HEADER WINAPI pdbFileHeaderA (PBYTE  pbPath,
                                   PDWORD pdVersion,
                                   PBOOL  pfInvalid);

PPDB_HEADER WINAPI pdbFileHeaderW (PWORD  pwPath,
                                   PDWORD pdVersion,
                                   PBOOL  pfInvalid);

DWORD WINAPI pdbFileLimit (PPDB_HEADER pph,
                           DWORD       dVersion);

BOOL WINAPI pdbFileUnused (PPDB_HEADER pph,
                           DWORD       dVersion,
                           DWORD       dStreamBytes,
                           PDWORD      pdPageBytes);

DWORD WINAPI pdbFilePages (PPDB_HEADER pph,
                           DWORD       dVersion,
                           DWORD       dStreamBytes,
                           PDWORD      pdPageBytes,
                           PBOOL       pfUnused);

PVOID WINAPI pdbFileRead (PPDB_HEADER pph,
                          DWORD       dVersion,
                          DWORD       dStreamBytes,
                          PVOID       pPages,
                          PBOOL       pfUnused);

PPDB_ROOT WINAPI pdbFileRoot (PPDB_HEADER pph,
                              DWORD       dVersion,
                              PDWORD      pdStreams,
                              PDWORD      pdStreamBytes,
                              PBOOL       pfUnused);

PVOID WINAPI pdbFileStream (PPDB_HEADER pph,
                            PPDB_ROOT   ppr,
                            DWORD       dVersion,
                            DWORD       dStreamID,
                            PDWORD      pdStreamBytes,
                            PBOOL       pfUnused);

PPDB_FILE WINAPI pdbFileOpenA (PBYTE pbPath,
                               PBOOL pfInvalid);

PPDB_FILE WINAPI pdbFileOpenW (PWORD pwPath,
                               PBOOL pfInvalid);

PPDB_FILE WINAPI pdbFileClose (PPDB_FILE ppf);

PVOID WINAPI pdbFileExtract (PPDB_FILE ppf,
                             DWORD     dStreamID,
                             PDWORD    pdStreamBytes,
                             PBOOL     pfUnused);

PPDB_DATA WINAPI pdbFileData (PPDB_FILE ppf);

PPDB_DATA WINAPI pdbDataOpenA (PBYTE pbPath,
                               PBOOL pfInvalid);

PPDB_DATA WINAPI pdbDataOpenW (PWORD pwPath,
                               PBOOL pfInvalid);

PPDB_DATA WINAPI pdbDataClose (PPDB_DATA ppd);

// =================================================================
// LINKER CONTROL
// =================================================================

#ifdef _SBS_PDB_DLL_

#pragma comment (linker, "/entry:\"DllMain\"")

#else

#pragma comment (linker, "/defaultlib:sbs_pdb.lib")

#endif

////////////////////////////////////////////////////////////////////
#endif // #ifndef _RC_PASS_
////////////////////////////////////////////////////////////////////

// =================================================================
// END OF FILE
// =================================================================
