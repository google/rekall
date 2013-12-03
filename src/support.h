#include <Python.h>
#include <stdint.h>
#include <stdbool.h>


static char AMD64PagedMemory__doc__[] = "Standard AMD 64-bit address space.\n"
"\n"
"    Provides an address space for AMD64 paged memory, aka the x86_64\n"
"    architecture, which is laid out similarly to Physical Address\n"
"    Extensions (PAE). Allows callers to map virtual address to\n"
"    offsets in physical memory.\n"
"\n"
"    Create a new AMD64 address space to sit on top of the base address\n"
"    space and a Directory Table Base (CR3 value) of 'dtb'.\n"
"\n"
"    Comments in this class mostly come from the Intel(R) 64 and IA-32\n"
"    Architectures Software Developer's Manual Volume 3A: System Programming\n"
"    Guide, Part 1, revision 031, pages 4-8 to 4-15. This book is available\n"
"    for free at http://www.intel.com/products/processor/manuals/index.htm.\n"
"    Similar information is also available from Advanced Micro Devices (AMD)\n"
"    at http://support.amd.com/us/Processor_TechDocs/24593.pdf.\n"
"    \n";

// Reads must stay below this size to protect process memory usage.
#define MAX_READ_LENGTH 100 * 1024 * 1024


#define MIN(X,Y) ((X) < (Y) ? (X) : (Y))


/* Looking up a page table may fill all these value. */
typedef struct {
  // For each page table entry we collect the address and the value of it.
  uint64_t pml4e_addr;
  uint64_t pml4e;
  uint64_t pdpte_addr;
  uint64_t pdpte;
  uint64_t pde_addr;
  uint64_t pde;
  uint64_t pte_addr;
  uint64_t pte;
  uint64_t paddr;
} page_table_lookup;

typedef struct AMD64PagedMemory_t {
  PyObject_HEAD
  PyObject *base;
  uint64_t dtb;
  int (*_read)(struct AMD64PagedMemory_t *self, uint64_t offset,
               uint64_t length, char *out);
} AMD64PagedMemory;

static int AMD64PagedMemory_init(AMD64PagedMemory *self, PyObject *args,
                                 PyObject *kwds);





static uint64_t _unpack_uint64(unsigned char *str);
static uint64_t _read_long_long_phys(AMD64PagedMemory *self, uint64_t address);
static int _vtop(AMD64PagedMemory *self, uint64_t vaddr,
                 page_table_lookup *result);
