// Implements a raw pci access method for communicating with the pci
// controller directly.
#include "winpmem.h"

#define PCI_VENDOR_ID           0x00    /* 16 bits */
#define PCI_DEVICE_ID           0x02    /* 16 bits */
#define PCI_COMMAND             0x04    /* 16 bits */
#define PCI_COMMAND_IO          0x01
#define PCI_COMMAND_MEMORY      0x02

#define PCI_BASE_ADDRESS_0      0x10    /* 32 bits */
#define PCI_BASE_ADDRESS_1      0x14    /* 32 bits [htype 0,1 only] */
#define PCI_BASE_ADDRESS_2      0x18    /* 32 bits [htype 0 only] */
#define PCI_BASE_ADDRESS_3      0x1c    /* 32 bits */
#define PCI_BASE_ADDRESS_4      0x20    /* 32 bits */
#define PCI_BASE_ADDRESS_5      0x24    /* 32 bits */
#define  PCI_BASE_ADDRESS_SPACE 0x01    /* 0 = memory, 1 = I/O */
#define  PCI_BASE_ADDRESS_SPACE_IO 0x01
#define  PCI_BASE_ADDRESS_SPACE_MEMORY 0x00
#define  PCI_BASE_ADDRESS_MEM_TYPE_MASK 0x06
#define  PCI_BASE_ADDRESS_MEM_TYPE_32   0x00    /* 32 bit address */
#define  PCI_BASE_ADDRESS_MEM_TYPE_1M   0x02    /* Below 1M [obsolete] */
#define  PCI_BASE_ADDRESS_MEM_TYPE_64   0x04    /* 64 bit address */
#define  PCI_BASE_ADDRESS_MEM_PREFETCH  0x08    /* prefetchable? */
#define  PCI_BASE_ADDRESS_MEM_MASK      (~(pciaddr_t)0x0f)
#define  PCI_BASE_ADDRESS_IO_MASK       (~(pciaddr_t)0x03)
/* bit 1 is reserved if address_space = 1 */


#define PCI_IO_BASE             0x1c    /* I/O range behind the bridge */
#define PCI_IO_LIMIT            0x1d
#define PCI_MEMORY_BASE         0x20    /* Memory range behind */
#define PCI_MEMORY_LIMIT        0x22
#define PCI_PREF_MEMORY_BASE    0x24    /* Prefetchable memory range behind */
#define PCI_PREF_MEMORY_LIMIT   0x26
#define PCI_PREF_BASE_UPPER32   0x28    /* Upper half of prefetchable memory range */
#define PCI_PREF_LIMIT_UPPER32  0x2c
#define PCI_IO_BASE_UPPER16     0x30    /* Upper half of I/O addresses */
#define PCI_IO_LIMIT_UPPER16    0x32


#define PCI_CONFIG_DATA 0xCFC
#define PCI_CONFIG_ADDRESS 0xCF8

#define PCI_CLASS_REVISION      0x08    /* High 24 bits are class, low 8 revision */
#define PCI_HEADER_TYPE         0x0e    /* 8 bits */

NTSTATUS PCI_AddMemoryRanges(struct PmemMemoryInfo *info, int len);
