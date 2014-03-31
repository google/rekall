 /***************************************************************************
 * Intel VMCS layout discovery module. 64-bit hosts only.
 * Author: Jordi Sanchez <parki.san@gmail.com>
 *
 * This module attempts to generate a rekall profile of the Virtual Machine
 * Control Structure of the host machine.
 *
 * I took some bits of Vish Mohan's VT-x initialization code at
 * (https://github.com/vishmohan/vmlaunch)
 ***************************************************************************/


#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include "vmcs_layout.h"

MODULE_LICENSE("GPL");

#define MYPAGE_SIZE 4096
#define IA32_VMX_BASIC_MSR 0x480
#define IA32_FEATURE_CONTROL_MSR 0x3A
#define IA32_VMX_PROCBASED_CTLS_MSR 0x482
#define IA32_VMX_PROCBASED_CTLS2_MSR 0x48B
#define IA32_VMX_TRUE_PROCBASED_CTLS_MSR 0x48E
#define CPUID_VMX_BIT 5
#define NOTFOUND 0xFFFFFFFF

// Needles used to discover the VMCS
#define CONSTANT16  0x1337
#define CONSTANT32  0x13371337ul
#define CONSTANT64  0x1337133713371337ull


bool alloc_failure = false;
int vmx_rev_id = 0;
int vmxon_success = 0;
int vmxoff_success = 0;
int vmptrld_success = 0;
int vmclear_success = 0;
int vmwrite_success = 0;
int vmread_success = 0;
int vmlaunch_success = 0;
char *vmxon_region;
char *vmcs_guest_region;

long int vmxon_phy_region = 0;
long int vmcs_phy_region = 0;
long int vmcs_alt_phy_region = 0;

long int rflags_value = 0;

inline static void store_rflags(void);
static void print_vmerror(void);
static void vmclear(long int*);
static void vmptrld(long int*);
static void vmxon_exit(void);
static u64 vmread(unsigned long field);

#define MAX_REGIONS 64
// Stores virtual addresses of memory regions.
unsigned char *regions[MAX_REGIONS];
// Stores physical addresses of memory regions.
long int phy_regions[MAX_REGIONS];

#define MY_VMX_VMXON_RAX        ".byte 0xf3, 0x0f, 0xc7, 0x30"
#define MY_VMX_VMPTRLD_RAX      ".byte 0x0f, 0xc7, 0x30"
#define MY_VMX_VMCLEAR_RAX      ".byte 0x66, 0x0f, 0xc7, 0x30"
#define MY_VMX_VMLAUNCH         ".byte 0x0f, 0x01, 0xc2"
#define MY_VMX_VMRESUME         ".byte 0x0f, 0x01, 0xc3"
#define MY_VMX_VMREAD_RDX_RAX   ".byte 0x0f, 0x78, 0xd0"
#define MY_VMX_VMWRITE_RAX_RDX  ".byte 0x0f, 0x79, 0xd0"
#define MY_VMX_VMXOFF           ".byte 0x0f, 0x01, 0xc4"
#define MY_VMX_VMCALL           ".byte 0x0f, 0x01, 0xc1"
#define MY_HLT                  ".byte 0xf4"


// Reads a VMCS field by its encoding.
static u64 vmread(unsigned long field) {
    u64 value = 0;
    vmread_success = 0;
    asm volatile("vmread %1, %0\n"
                 : "=a"(value) : "d"(field) : "cc");
    asm volatile("jbe vmread_fail\n");
    vmread_success = 1;
    asm volatile("jmp vmread_finish\n");
    asm volatile("vmread_fail:\n");
    store_rflags();
    printk("   # vmread(0x%lX) failed\n", field);
    printk("   # RFLAGS: 0x%lX\n", rflags_value);
    //printk("   # INSTR_ERROR: 0x%llX\n", vmread(VMX_INSTR_ERROR));
    vmread_success = 0;
    asm volatile("vmread_finish:\n");
    return value;
}

// Writes to a VMCS field by its encoding.
static void vmwrite(unsigned long field, unsigned long value) {
    asm volatile(MY_VMX_VMWRITE_RAX_RDX
                 : : "a"(value), "d"(field) : "cc");
    asm volatile("jbe vmwrite_fail\n");
    vmwrite_success = 1;
    asm volatile("jmp vmwrite_finish\n"
                 "vmwrite_fail:\n");
    store_rflags();
    vmwrite_success = 0;
    printk("   # vmwrite(0x%0lX, 0x%0lX) failed\n", field, value);
    print_vmerror();
    asm volatile("vmwrite_finish:\n");
}

/* Finds a 2-byte value in the physical page pointed by vmcs_phys_page and
 * returns the offset. If not found, returns NOTFOUND */
static unsigned int find_16(void *vmcs_phys_page, u16 value)
{
    unsigned int i = 0;
    for (; i < MYPAGE_SIZE - 2; i++)
    {
        if ((*(u16*)(vmcs_phys_page + i)) == value)
        {
            return i;
        }
    }
    return NOTFOUND;
}

/* Finds a 4-byte value in the physical page pointed by vmcs_phys_page and
 * returns the offset. If not found, returns NOTFOUND */
static int find_32(void *vmcs_phys_page, u32 value)
{
    unsigned int i = 0;
    for (; i < MYPAGE_SIZE - 4; i++)
    {
        if ((*(u32*)(vmcs_phys_page + i)) == value)
        {
            return i;
        }
    }
    return NOTFOUND;
}

/* Finds a 8-byte value in the physical page pointed by vmcs_phys_page and
 * returns the offset. If not found, returns NOTFOUND */
static int find_64(void *vmcs_phys_page, u64 value)
{
    unsigned int i = 0;
    for (; i < MYPAGE_SIZE - 8; i++)
    {
        if ((*(u64*)(vmcs_phys_page + i)) == value)
        {
            return i;
        }
    }
    return NOTFOUND;
}

/* Dumps out a memory region. */
static void print_region(char *region)
{
    int i;
    printk("[i] memory dump of region %p:\n[i] ", region);
    for (i=0; i<MYPAGE_SIZE; i++)
    {
        if (!(i % 4)) printk(" ");
        if (! (i % 8)) printk(" ");
        if (! (i % 32)) printk("\n[i] ");
        printk("%02x", *(unsigned char*)(region+i));
    }
    printk("\n");
}

/* Discovers the layout of the VMCS used by the processor in which
 * this module is being run. No attempts at discovery of other processors
 * is done on multi-processor systems.
 */
static void discover_vmcs(void)
{
    int i = 0;
    unsigned int index = 0;
    unsigned int result = 0;
    FIELD_INFO current_field;
    u64 field_value = 0;
    unsigned short saved_16 = 0;
    unsigned int saved_32 = 0;
    u64 saved_64 = 0;
    unsigned long encoding_width = 0;
    unsigned int field_index = 0;
    // By default, a field is not validated
    unsigned int validated = 0;
    unsigned int readonly = 0;
    int region_idx = 0;
    unsigned int found = 0;
    unsigned int needs_force_flush = 0;
    unsigned int is_high = 0;
    char *field_datatype = NULL;


    printk("[i] Force-flush testing...\n");
    /* 1) Force-flush testing.
     * Usually, the VMCS is maintained in memory, so after doing a vmptrld of a
     * memory region, any subsequent vmwrites will write to memory.
     *
     * Some processors (i.e: Xeon Westmere, Haswells) have in-chip storage of
     * the VMCS. Because we rely on being able to manipulate fields and see the
     * effect this has in memory, we need to first determine if we need to force
     * the processor to load the VMCS off memory.
     *
     * To check for it, we set up a control VMCS, load it and write a VMCS value
     * that's available in all VME revisions. Then, we try to find it in memory
     * in the same VMCS region that we marked as current.
     *
     * If we cannot find it, it means the processor is using alternate means to
     * store the VMCS.
     *
     * We then ask the processor to load as many memory regions as needed in
     * order to overflow its storage capacity and force it to dump our control
     * VMCS to memory. Once we find the needle in memory, we know the next
     * VMPTRLD will force the processor to load our control VMCS.
     */
    saved_64 = vmread(GUEST_CR3);
    printk("[i] Saved GUEST_CR3 = %llx\n", saved_64);
    vmwrite(GUEST_CR3, CONSTANT64);

    
    if (find_64(vmcs_guest_region, CONSTANT64) == NOTFOUND)
    {
        // Needle not found, so we'll probably need to force-flush.
        needs_force_flush = 1;
        printk("[i] Needle not found. Force-flush technique required.\n");

        // Initialize the force-flush regions.
        for (i = 0; i < MAX_REGIONS; i++)
        {
             phy_regions[i] = 0;
             regions[i] = NULL;
        }

        // We'll try to find how many additional VMCS we need to allocate to
        // force a flush.
        // We start allocating and switching the current_active VMCS and trying
        // to find it in the original VMCS, to see when/if it gets flushed to
        // memory.
        for(region_idx = 0; !found && (region_idx < MAX_REGIONS); region_idx++)
        {
            regions[region_idx] = kmalloc(MYPAGE_SIZE, GFP_KERNEL);
            // We need to fill the revision ID to make it a valid VMCS region.
            memcpy(regions[region_idx], &vmx_rev_id, 4);
            phy_regions[region_idx] = __pa(regions[region_idx]);

            printk("[i] Loading region %p (%016lX)\n",
                   regions[region_idx], phy_regions[region_idx]);
            vmcs_alt_phy_region = phy_regions[region_idx];
            vmptrld(&phy_regions[region_idx]);
            result = find_64(vmcs_guest_region, CONSTANT64);
            if (result != NOTFOUND)
            {
                found = 1;
                break;
            }
        }
        if (!found)
            printk("[!] NOT FOUND after %d regions.\n", region_idx + 1);
        else
        {
            printk("[i] FOUND AFTER %i regions, at offset %d\n",
                   region_idx + 1, result);
            print_region(vmcs_guest_region);
        }
        printk("[i] vmclearing and freeing %d regions\n", region_idx+1);
        for (i = 0; i < MAX_REGIONS && regions[i] != NULL; i++)
        {
            vmcs_alt_phy_region = phy_regions[i];
            vmclear(&phy_regions[i]);
            kfree(regions[i]);
        }
    } else
    {
        printk("[!] Needle found in memory. Force-flush is NOT required.\n");
    }

    /* 2) Actual discovery code
     * At this point if we had to force-flush regions we just overflowed the
     * processor's storage. The next VMPTRLD will force the processor to load
     * the region from memory, thus allowing us to. It could happen that the
     * processor could automatically load memory regions from disk as we VMCLEAR
     * them. However, I've never seen this happen (yet).
     *
     * Now, we fill the vmcs_guest region with 16 bit values which are the
     * indexes into the vmcs to help us locate fields (even read-only ones).
     * */
    for (index=4; index < MYPAGE_SIZE; index += 2)
    {
        *(unsigned short*)(vmcs_guest_region + index) = index;
    }
    memcpy(vmcs_guest_region, &vmx_rev_id, 4);

    if (needs_force_flush)
    {
        // With the region filled in, we force the processor to load it.
        // Because this was not the current active VMCS region, and we forced a
        // flush to memory earlier, this region now HAS to be loaded by the
        // processor from memory, leaking the positions of all the available
        // fields.
        vmptrld(&vmcs_phy_region);
        printk("[i] Will NOT write-validate fields.\n");
    }

    printk("[i] ---COPY HERE--- What follows is your profile.\n");
    printk("{\n");
    printk(" \"$STRUCTS\" {\n");
    printk("  \"NEW_VMCS_0x%X\": [4096, {\n", vmx_rev_id);

    for (i = 0, current_field = field_table[i];
         current_field.field_name != NULL;
         current_field = field_table[++i])
    {
        field_value = vmread(current_field.encoding);
        if (vmread_success == 0)
        {
            printk("   # %s\tINVALID_FIELD\n", current_field.field_name);
            continue;
        }

        // First validation step
        field_index = field_value & 0xFFFFull;
        if (field_index < 0x8)
        {
            // A field cannot exist at offset below 8 because 0 is the
            // REVISION_ID and 4 is the ABORT_INDICATOR.
            // Contrary to what the manuals say, vmread always seems to succeed
            // (at least for known encodings), even for fields that are not
            // present on a microarchitecture, so you usually get a value of 0
            // for fields that are not valid.
            // TODO: Consider confirming these cases with a vmwrite that fails.
            printk("   # %s reported being at offset %d which is impossible\n",
                   current_field.field_name, field_index);
            continue;
        }
        // Some fields are not aligned to 2... here we try to fix the reported
        // value.
        // This is mostly just the segment selectors for now.
        // According to the manuals, the VMCS only fills the first 1K of the
        // page, so we set w, we assu
        if ( field_index > 0x1000)
        {
            // !!WARNING!! HACK HACK HACK for values not aligned to 2.
            printk("   # %s\t%d\tMISALIGNED\n",
                   current_field.field_name, field_index);
            field_index = (((field_index & 0xFF00) >> 8)
                           | ((field_index & 0x00FF) << 8)) - 1;
            printk("   # %s\t%d\tFIXED\n",
                   current_field.field_name, field_index);
        }

        if (field_index > 0x1000)
        {
            // This is outside the range of the VMCS guest region. Cannot be
            // valid or it was written to between our initialization and the
            // discovery code :(
            printk("   # %s\t%d\tOFFBOUNDS\n", current_field.field_name,
                   field_index);
            continue;
        }

        // Reset the validation flag
        validated = 0;
        // Reset the HIGH field flag
        is_high = 0;
        // The width is encoded in bits 14:13
        encoding_width = (current_field.encoding & ((1<<14) | (1<<13))) >> 13;
        // Field is read-only if bits 11:10 == 1
        readonly = ((current_field.encoding & ((1<<11) | (1<<10))) >> 10) == 1;
        // Field holds only the HIGH bytes if it's 64-bits wide and bit 1 is set
        is_high = encoding_width == 1 && current_field.encoding & 1;

        // Second validation, for writable fields only. We attempt to write to
        // it and confirm the offset where we find it.
        if (!readonly && !needs_force_flush)
        { // No validation possible with readonly fields :(
            if (encoding_width == 0)
            { // 16-bit fields
                saved_16 = field_value;
                vmwrite(current_field.encoding, CONSTANT16);
                result = find_16(vmcs_guest_region, CONSTANT16);
                vmwrite(current_field.encoding, field_value);
                field_datatype = "unsigned short";
            } else
            if (encoding_width == 2)
            { // 32-bit fields
                saved_32 = field_value;
                vmwrite(current_field.encoding, CONSTANT32);
                result = find_32(vmcs_guest_region, CONSTANT32);
                vmwrite(current_field.encoding, field_value);
                field_datatype = "unsigned int";
            } else
            if (encoding_width == 1)
            { // 64-bit fields
                vmwrite(current_field.encoding, CONSTANT64);
                if (current_field.encoding & 1)
                {   // This is a high field. High fields return 64:32 in 31:0.
                    // We need to look for a 32-bit value instead.
                    result = find_32(vmcs_guest_region, CONSTANT32);
                    field_datatype = "unsigned int";
                } else
                {
                    result = find_64(vmcs_guest_region, CONSTANT64);
                    field_datatype = "unsigned long long";
                }
                vmwrite(current_field.encoding, field_value);
            } else
            if (encoding_width == 3)
            { // Natural-width fields, which are 64 bits in a 64bit OS.
                vmwrite(current_field.encoding, CONSTANT64);
                result = find_64(vmcs_guest_region, CONSTANT64);
                vmwrite(current_field.encoding, field_value);
                field_datatype = "unsigned long";
            }

            if (result == field_index)
                validated = 1;
            else
                printk("   # reported_index = %X | found_index = %X\n",
                       field_index, result);
        }


        printk("   \"%s\": [%d, [\"%s\", {}]],\n", current_field.field_name,
               field_index, field_datatype);
    }
    printk("   }]\n");
    printk(" },\n");
    printk(" \"$METADATA\": {\n");
    printk("  \"ProfileClass\": \"VMCSProfile\"\n");
    printk(" }\n");
    printk("}\n");
    printk("[i] ---END HERE--- Profile ends here.\n");
}


/* Allocate a 4K region for vmxon */
static void allocate_vmxon_region(void)
{
    vmxon_region = kmalloc(MYPAGE_SIZE, GFP_KERNEL);
}

/* Allocate a 4K vmcs region for the guest */
static void allocate_vmcs_region(void)
{
    vmcs_guest_region = kmalloc(MYPAGE_SIZE, GFP_KERNEL);
    memset(vmcs_guest_region, 0, MYPAGE_SIZE);
}

static void deallocate_vmxon_region(void)
{
    if (vmxon_region)
    {
        printk("[i] freeing allocated vmxon region!\n");
        kfree(vmxon_region);
    }
}

static void deallocate_vmcs_region(void)
{
    if (vmcs_guest_region)
    {
        printk("[i] freeing allocated vmcs region!\n");
        kfree(vmcs_guest_region);
    }
}

static void turn_on_vmxe(void)
{
    asm volatile("push %rax\n"
                 "movq %cr4, %rax\n"
                 "bts $13, %rax\n"
                 "movq %rax, %cr4\n"
                 "pop %rax\n");
    printk("[i] turned on cr4.vmxe\n");
}

static void turn_off_vmxe(void)
{
    asm volatile("push %rax\n"
                 "movq %cr4, %rax\n"
                 "btr $13, %rax\n"
                 "movq %rax, %cr4\n"
                 "pop %rax\n");
    printk("[i] turned off cr4.vmxe\n");
}

inline void store_rflags(void)
{
    asm volatile("pushfq\n");
    asm volatile("popq %0\n"
                 :
                 :"m"(rflags_value)
                 :"memory");
}

static void print_vmerror(void)
{
    printk("   # Error code: %llX\n", vmread(INSTR_ERROR));
    printk("   # RFLAGS: 0x%lX\n", rflags_value);
}

/*do vmptrld*/
static void vmptrld(long int *region) {
    printk("[i] Attempting vmptrld(0x%lX) ... ", *region);
    asm volatile(MY_VMX_VMPTRLD_RAX
                 :
		 : "a"(region), "m"(*region)
                 : "cc", "memory");
    asm volatile("jbe vmptrld_fail\n");
    vmptrld_success = 1;
    printk("ok!\n");
    asm volatile("jmp vmptrld_finish\n"
                 "vmptrld_fail:\n");
    store_rflags();
    vmptrld_success = 0;
    printk("fail!\n");
    print_vmerror();
    asm volatile("vmptrld_finish:\n");
}

static void vmclear(long int *region)
{
    asm volatile(MY_VMX_VMCLEAR_RAX
                 :
                 : "a"(region), "m"(*region)
                 : "cc", "memory");
    asm volatile("jbe vmclear_fail");
    vmclear_success = 1;
    asm volatile("jmp vmclear_finish\n"
                 "vmclear_fail:\n");
    store_rflags();
    vmclear_success = 0;
    printk("[i] vmclear has failed!\n");
    print_vmerror();
    asm volatile("vmclear_finish:\n");
    printk("[i] vmclear done!\n");
}

static void vmxon(void)
{
    asm volatile(MY_VMX_VMXON_RAX
                 :
                 : "a"(&vmxon_phy_region), "m"(vmxon_phy_region)
                 : "memory", "cc");
    asm volatile("jbe vmxon_fail\n");
    vmxon_success = 1;
    asm volatile("jmp vmxon_finish\n"
                 "vmxon_fail:\n");
    store_rflags();
    vmxon_success = 0;
    printk("[i] vmxon has failed!\n");
    print_vmerror();
    asm volatile("vmxon_finish:\n");
}

/*do vmxoff*/
static void vmxoff(void)
{
    asm volatile("vmxoff\n" : : : "cc");
    asm volatile("jbe vmxoff_fail\n");
    vmxoff_success = 1;
    asm volatile("jmp vmxoff_finish\n");
    asm volatile("vmxoff_fail:\n");
    store_rflags();
    vmxoff_success = 0;
    printk("[i] vmxoff has failed!\n");
    print_vmerror();
    asm volatile("vmxoff_finish:\n");
    printk("[i] vmxoff complete\n");
}


static void vmxon_exit(void)
{
    if (vmxon_success == 1)
    {
        printk("[i] Machine in vmxon: Attempting vmxoff\n");
        vmclear(&vmcs_phy_region);
        vmxoff();
        vmxon_success = 0;
    }
    turn_off_vmxe();
    deallocate_vmcs_region();
    deallocate_vmxon_region();
}

static void vmxon_cleanup(void)
{
    printk(KERN_INFO "[i] VMRE module exitting\n");
}

uint64_t readmsr(uint32_t msr)
{
    uint64_t msr_value;
    asm volatile("rdmsr" : "=A"(msr_value) : "c"(msr));
    return msr_value;
}

static int vmxon_init(void)
{
    int cpuid_leaf = 1;
    int cpuid_ecx = 0;
    uint64_t msr3a_value = 0;

    printk("[i] In vmxon\n");

    asm volatile("cpuid\n\t"
                 : "=c"(cpuid_ecx)
                 : "a"(cpuid_leaf)
                 : "%rbx", "%rdx");

    if ((cpuid_ecx >> CPUID_VMX_BIT) & 1)
    {
        printk("[i] VMX supported CPU.\n");
    } else
    {
        printk("[i] VMX not supported by CPU. Not doing anything\n");
        goto finish_here;
    }

    msr3a_value = readmsr(IA32_FEATURE_CONTROL_MSR);
    printk("[i] IA32_FEATURE_CONTROL_MSR = %llX\n", msr3a_value);
    printk("[i] IA32_VMX_BASIC_MSR = %llX\n", readmsr(IA32_VMX_BASIC_MSR));
    if (readmsr(IA32_VMX_BASIC_MSR) & (1ull<<55))
    {
        printk("[i] TRUE VMX controls supported\n");
        printk("[i] IA32_VMX_PROCBASED_CTLS = %llX\n",
              readmsr(IA32_VMX_PROCBASED_CTLS_MSR));
        printk("[i] IA32_VMX_PROCBASED_CTLS2 = %llX\n",
              readmsr(IA32_VMX_PROCBASED_CTLS2_MSR));
        printk("[i] IA32_VMX_TRUE_PROCBASED_CTLS = %llX\n",
               readmsr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR));
    } else
    {
        printk("[i] TRUE VMX controls UNSUPPORTED\n");
        printk("[i] IA32_VMX_PROCBASED_CTLS = %llX\n",
               readmsr(IA32_VMX_PROCBASED_CTLS_MSR));
        printk("[i] IA32_VMX_PROCBASED_CTLS2 = %llX\n",
              readmsr(IA32_VMX_PROCBASED_CTLS2_MSR));
    }

    if (msr3a_value & 1)
    {
        if ((msr3a_value >> 2) & 1)
        {
            printk("[i] MSR 0x3A: Lock bit is on. VMXON bit is on. OK\n");
        } else
        {
            printk("[i] MSR 0x3A: Lock bit is on. VMXON bit is off. No VME :(\n");
            goto finish_here;
        }
    } else
    {
        printk("[i] MSR 0x3A: Lock bit is not on. Not doing anything."
               "You should activate VT-x.\n");
        goto finish_here;
    }

    allocate_vmxon_region();

    if (vmxon_region == NULL)
    {
        printk("[i] Error allocating vmxon region\n");
        vmxon_exit();
        vmxon_success = -ENOMEM;
        return vmxon_success;
    }

    vmxon_phy_region = __pa(vmxon_region);
    vmx_rev_id = readmsr(IA32_VMX_BASIC_MSR);
    printk("[i] Revision ID: 0x%08X\n", vmx_rev_id);
    memcpy(vmxon_region, &vmx_rev_id, 4);  // copy revision id to vmxon region

    turn_on_vmxe();
    vmxon();
    if (!vmxon_success)
    {
        deallocate_vmxon_region();
        goto finish_here;
    }
    allocate_vmcs_region();

    if (vmcs_guest_region == NULL)
    {
        printk("[i] Error allocating vmcs guest regions\n");
        vmxon_exit();
        vmptrld_success = -ENOMEM;
        return vmptrld_success;
    }
    vmcs_phy_region = __pa(vmcs_guest_region);
    memcpy(vmcs_guest_region, &vmx_rev_id, 4); //copy revision id to vmcs region
    vmptrld(&vmcs_phy_region);
    printk("[i] Finished vmxon\n");
    printk("[i] Revision ID: 0x%08X\n", vmx_rev_id);
    printk(KERN_INFO "[i] Discovering fields\n");
    discover_vmcs();
    vmxon_exit();
finish_here:
    return 0;
}


module_init(vmxon_init);
module_exit(vmxon_cleanup);
