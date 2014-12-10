
---
layout: plugin
title: check_idt
abstract: |
     Checks if the IDT has been altered 

epydoc: rekall.plugins.linux.check_idt.CheckIdt-class.html
---

This plugin tries to identify the symbol name or location of each entry in the
Interrupt Descriptor Table. 

The IDT holds a list of gate descriptors. These descriptor can be task, trap or
interrupt descriptors.

 * Interrupt Gates are invoked via the `int` instruction. System calls,
   for example, can be invoked in Linux with an `int 0x80` instruction.
 * Trap Gates are also invoked via the `int` instruction but don't modify the
   IF flag in the EFLAGS register.
 * Task Gates were originally intended to facilitate task switching but are
   mostly not used nowadays.

The plugin provides 6 columns as output:

  * __Index__: The gate number.
  * __Address__: The kernel address of the gate handler.
  * __Type__: Whether this is an int/trap/task gate.
  * __Present__: If the gate descriptor is present.
  * __DPL__: Descriptor Privilege Level. The highest ring that is allowed to call
    this gate.
  * __Symbol__: The kernel symbol that the address points to. If it's unknown
    but within the kernel image, it will be `Kernel`. Otherwise, `Unknown`.

### Notes
 * A value of `Kernel` in the __Symbol__ column means "as part of the kernel
   image", not that it's anywhere in the kernel address space.
 * Rekall currently only validates the IDT at the address pointed by the kernel
   symbol `idt_table`. Note that on a running system, the current IDT may be
   different as it can be changed via the x86 `lidt` instruction.
 * Entries 0x00 to 0x1F are reserved by Intel for processor exceptions.


### Sample output

```
$ python rekall/rekal.py --de -f ~/projects/actaeon64/memory_images/Windows7_VMware\(Win7x64+Ubuntu686\,Ubuntu64\)_VBox\(XPSP3x86\).ram --profile_path ../rekall-profiles/ --profile_path ../my-profiles/  --ept 0x17725001E check_idt
Index    Address                   Type Present DPL Symbol                        
----- -------------- ------------------ ------- --- ------------------------------
  0x0 0xffff816f6970    32-bit Int Gate       1   0 divide_error                  
  0x1 0xffff816ecc80    32-bit Int Gate       1   0 Kernel                        
  0x2 0xffff816ed0b0    32-bit Int Gate       1   0 nmi                           
  0x3 0xffff816eccc0    32-bit Int Gate       1   3 int3                          
  0x4 0xffff816f69a0    32-bit Int Gate       1   3 overflow                      
  0x5 0xffff816f69d0    32-bit Int Gate       1   0 bounds                        
  0x6 0xffff816f6a00    32-bit Int Gate       1   0 invalid_op                    
  0x7 0xffff816f6a30    32-bit Int Gate       1   0 device_not_available          
  0x8 0xffff816f6a60    32-bit Int Gate       1   0 double_fault                  
  0x9 0xffff816f6a90    32-bit Int Gate       1   0 coprocessor_segment_overrun   
  0xa 0xffff816f6ac0    32-bit Int Gate       1   0 invalid_TSS                   
  0xb 0xffff816f6af0    32-bit Int Gate       1   0 segment_not_present           
  0xc 0xffff816ecd00    32-bit Int Gate       1   0 stack_segment                 
  0xd 0xffff816ecdc0    32-bit Int Gate       1   0 general_protection            
  0xe 0xffff816ecdf0    32-bit Int Gate       1   0 page_fault                    
  0xf 0xffff816f6b20    32-bit Int Gate       1   0 spurious_interrupt_bug        
 0x10 0xffff816f6b50    32-bit Int Gate       1   0 coprocessor_error             
 0x11 0xffff816f6b80    32-bit Int Gate       1   0 alignment_check               
 0x12 0xffff816ece50    32-bit Int Gate       1   0 machine_check                 
 0x13 0xffff816f6bb0    32-bit Int Gate       1   0 simd_coprocessor_error        
 0x14 0xffff81d260b4    32-bit Int Gate       1   0 Unknown                       
 0x15 0xffff81d260bd    32-bit Int Gate       1   0 Unknown                       
 0x16 0xffff81d260c6    32-bit Int Gate       1   0 Unknown                       
 0x17 0xffff81d260cf    32-bit Int Gate       1   0 Unknown                       
 0x18 0xffff81d260d8    32-bit Int Gate       1   0 Unknown                       
 0x19 0xffff81d260e1    32-bit Int Gate       1   0 Unknown                       
 0x1a 0xffff81d260ea    32-bit Int Gate       1   0 Unknown                       
 0x1b 0xffff81d260f3    32-bit Int Gate       1   0 Unknown                       
 0x1c 0xffff81d260fc    32-bit Int Gate       1   0 Unknown                       
 0x1d 0xffff81d26105    32-bit Int Gate       1   0 Unknown                       
 0x1e 0xffff81d2610e    32-bit Int Gate       1   0 Unknown                       
 0x1f 0xffff81d26117    32-bit Int Gate       1   0 Unknown                       
 0x20 0xffff816f5e00    32-bit Int Gate       1   0 irq_move_cleanup_interrupt    
 0x21 0xffff816f5a04    32-bit Int Gate       1   0 Kernel                        
 0x22 0xffff816f5a08    32-bit Int Gate       1   0 Kernel                        
 0x23 0xffff816f5a0c    32-bit Int Gate       1   0 Kernel                        
 0x24 0xffff816f5a10    32-bit Int Gate       1   0 Kernel                        
 0x25 0xffff816f5a14    32-bit Int Gate       1   0 Kernel                        
 0x26 0xffff816f5a18    32-bit Int Gate       1   0 Kernel                        
 0x27 0xffff816f5a20    32-bit Int Gate       1   0 Kernel                        
 0x28 0xffff816f5a24    32-bit Int Gate       1   0 Kernel                        
 0x29 0xffff816f5a28    32-bit Int Gate       1   0 Kernel                        
 0x2a 0xffff816f5a2c    32-bit Int Gate       1   0 Kernel                        
 0x2b 0xffff816f5a30    32-bit Int Gate       1   0 Kernel                        
 0x2c 0xffff816f5a34    32-bit Int Gate       1   0 Kernel                        
 0x2d 0xffff816f5a38    32-bit Int Gate       1   0 Kernel                        
 0x2e 0xffff816f5a40    32-bit Int Gate       1   0 Kernel                        
 0x2f 0xffff816f5a44    32-bit Int Gate       1   0 Kernel                        
 0x30 0xffff816f5a48    32-bit Int Gate       1   0 Kernel                        
 0x31 0xffff816f5a4c    32-bit Int Gate       1   0 Kernel                        
 0x32 0xffff816f5a50    32-bit Int Gate       1   0 Kernel                        
 0x33 0xffff816f5a54    32-bit Int Gate       1   0 Kernel                        
 0x34 0xffff816f5a58    32-bit Int Gate       1   0 Kernel                        
 0x35 0xffff816f5a60    32-bit Int Gate       1   0 Kernel                        
 0x36 0xffff816f5a64    32-bit Int Gate       1   0 Kernel                        
 0x37 0xffff816f5a68    32-bit Int Gate       1   0 Kernel                        
 0x38 0xffff816f5a6c    32-bit Int Gate       1   0 Kernel                        
 0x39 0xffff816f5a70    32-bit Int Gate       1   0 Kernel                        
 0x3a 0xffff816f5a74    32-bit Int Gate       1   0 Kernel                        
 0x3b 0xffff816f5a78    32-bit Int Gate       1   0 Kernel                        
 0x3c 0xffff816f5a80    32-bit Int Gate       1   0 Kernel                        
 0x3d 0xffff816f5a84    32-bit Int Gate       1   0 Kernel                        
 0x3e 0xffff816f5a88    32-bit Int Gate       1   0 Kernel                        
 0x3f 0xffff816f5a8c    32-bit Int Gate       1   0 Kernel                        
 0x40 0xffff816f5a90    32-bit Int Gate       1   0 Kernel                        
 0x41 0xffff816f5a94    32-bit Int Gate       1   0 Kernel                        
 0x42 0xffff816f5a98    32-bit Int Gate       1   0 Kernel                        
 0x43 0xffff816f5aa0    32-bit Int Gate       1   0 Kernel                        
 0x44 0xffff816f5aa4    32-bit Int Gate       1   0 Kernel                        
 0x45 0xffff816f5aa8    32-bit Int Gate       1   0 Kernel                        
 0x46 0xffff816f5aac    32-bit Int Gate       1   0 Kernel                        
 0x47 0xffff816f5ab0    32-bit Int Gate       1   0 Kernel                        
 0x48 0xffff816f5ab4    32-bit Int Gate       1   0 Kernel                        
 0x49 0xffff816f5ab8    32-bit Int Gate       1   0 Kernel                        
 0x4a 0xffff816f5ac0    32-bit Int Gate       1   0 Kernel                        
 0x4b 0xffff816f5ac4    32-bit Int Gate       1   0 Kernel                        
 0x4c 0xffff816f5ac8    32-bit Int Gate       1   0 Kernel                        
 0x4d 0xffff816f5acc    32-bit Int Gate       1   0 Kernel                        
 0x4e 0xffff816f5ad0    32-bit Int Gate       1   0 Kernel                        
 0x4f 0xffff816f5ad4    32-bit Int Gate       1   0 Kernel                        
 0x50 0xffff816f5ad8    32-bit Int Gate       1   0 Kernel                        
 0x51 0xffff816f5ae0    32-bit Int Gate       1   0 Kernel                        
 0x52 0xffff816f5ae4    32-bit Int Gate       1   0 Kernel                        
 0x53 0xffff816f5ae8    32-bit Int Gate       1   0 Kernel                        
 0x54 0xffff816f5aec    32-bit Int Gate       1   0 Kernel                        
 0x55 0xffff816f5af0    32-bit Int Gate       1   0 Kernel                        
 0x56 0xffff816f5af4    32-bit Int Gate       1   0 Kernel                        
 0x57 0xffff816f5af8    32-bit Int Gate       1   0 Kernel                        
 0x58 0xffff816f5b00    32-bit Int Gate       1   0 Kernel                        
 0x59 0xffff816f5b04    32-bit Int Gate       1   0 Kernel                        
 0x5a 0xffff816f5b08    32-bit Int Gate       1   0 Kernel                        
 0x5b 0xffff816f5b0c    32-bit Int Gate       1   0 Kernel                        
 0x5c 0xffff816f5b10    32-bit Int Gate       1   0 Kernel                        
 0x5d 0xffff816f5b14    32-bit Int Gate       1   0 Kernel                        
 0x5e 0xffff816f5b18    32-bit Int Gate       1   0 Kernel                        
 0x5f 0xffff816f5b20    32-bit Int Gate       1   0 Kernel                        
 0x60 0xffff816f5b24    32-bit Int Gate       1   0 Kernel                        
 0x61 0xffff816f5b28    32-bit Int Gate       1   0 Kernel                        
 0x62 0xffff816f5b2c    32-bit Int Gate       1   0 Kernel                        
 0x63 0xffff816f5b30    32-bit Int Gate       1   0 Kernel                        
 0x64 0xffff816f5b34    32-bit Int Gate       1   0 Kernel                        
 0x65 0xffff816f5b38    32-bit Int Gate       1   0 Kernel                        
 0x66 0xffff816f5b40    32-bit Int Gate       1   0 Kernel                        
 0x67 0xffff816f5b44    32-bit Int Gate       1   0 Kernel                        
 0x68 0xffff816f5b48    32-bit Int Gate       1   0 Kernel                        
 0x69 0xffff816f5b4c    32-bit Int Gate       1   0 Kernel                        
 0x6a 0xffff816f5b50    32-bit Int Gate       1   0 Kernel                        
 0x6b 0xffff816f5b54    32-bit Int Gate       1   0 Kernel                        
 0x6c 0xffff816f5b58    32-bit Int Gate       1   0 Kernel                        
 0x6d 0xffff816f5b60    32-bit Int Gate       1   0 Kernel                        
 0x6e 0xffff816f5b64    32-bit Int Gate       1   0 Kernel                        
 0x6f 0xffff816f5b68    32-bit Int Gate       1   0 Kernel                        
 0x70 0xffff816f5b6c    32-bit Int Gate       1   0 Kernel                        
 0x71 0xffff816f5b70    32-bit Int Gate       1   0 Kernel                        
 0x72 0xffff816f5b74    32-bit Int Gate       1   0 Kernel                        
 0x73 0xffff816f5b78    32-bit Int Gate       1   0 Kernel                        
 0x74 0xffff816f5b80    32-bit Int Gate       1   0 Kernel                        
 0x75 0xffff816f5b84    32-bit Int Gate       1   0 Kernel                        
 0x76 0xffff816f5b88    32-bit Int Gate       1   0 Kernel                        
 0x77 0xffff816f5b8c    32-bit Int Gate       1   0 Kernel                        
 0x78 0xffff816f5b90    32-bit Int Gate       1   0 Kernel                        
 0x79 0xffff816f5b94    32-bit Int Gate       1   0 Kernel                        
 0x7a 0xffff816f5b98    32-bit Int Gate       1   0 Kernel                        
 0x7b 0xffff816f5ba0    32-bit Int Gate       1   0 Kernel                        
 0x7c 0xffff816f5ba4    32-bit Int Gate       1   0 Kernel                        
 0x7d 0xffff816f5ba8    32-bit Int Gate       1   0 Kernel                        
 0x7e 0xffff816f5bac    32-bit Int Gate       1   0 Kernel                        
 0x7f 0xffff816f5bb0    32-bit Int Gate       1   0 Kernel                        
 0x80 0xffff816f72e0    32-bit Int Gate       1   3 ia32_syscall                  
 0x81 0xffff816f5bb8    32-bit Int Gate       1   0 Kernel                        
 0x82 0xffff816f5bc0    32-bit Int Gate       1   0 Kernel                        
 0x83 0xffff816f5bc4    32-bit Int Gate       1   0 Kernel                        
 0x84 0xffff816f5bc8    32-bit Int Gate       1   0 Kernel                        
 0x85 0xffff816f5bcc    32-bit Int Gate       1   0 Kernel                        
 0x86 0xffff816f5bd0    32-bit Int Gate       1   0 Kernel                        
 0x87 0xffff816f5bd4    32-bit Int Gate       1   0 Kernel                        
 0x88 0xffff816f5bd8    32-bit Int Gate       1   0 Kernel                        
 0x89 0xffff816f5be0    32-bit Int Gate       1   0 Kernel                        
 0x8a 0xffff816f5be4    32-bit Int Gate       1   0 Kernel                        
 0x8b 0xffff816f5be8    32-bit Int Gate       1   0 Kernel                        
 0x8c 0xffff816f5bec    32-bit Int Gate       1   0 Kernel                        
 0x8d 0xffff816f5bf0    32-bit Int Gate       1   0 Kernel                        
 0x8e 0xffff816f5bf4    32-bit Int Gate       1   0 Kernel                        
 0x8f 0xffff816f5bf8    32-bit Int Gate       1   0 Kernel                        
 0x90 0xffff816f5c00    32-bit Int Gate       1   0 Kernel                        
 0x91 0xffff816f5c04    32-bit Int Gate       1   0 Kernel                        
 0x92 0xffff816f5c08    32-bit Int Gate       1   0 Kernel                        
 0x93 0xffff816f5c0c    32-bit Int Gate       1   0 Kernel                        
 0x94 0xffff816f5c10    32-bit Int Gate       1   0 Kernel                        
 0x95 0xffff816f5c14    32-bit Int Gate       1   0 Kernel                        
 0x96 0xffff816f5c18    32-bit Int Gate       1   0 Kernel                        
 0x97 0xffff816f5c20    32-bit Int Gate       1   0 Kernel                        
 0x98 0xffff816f5c24    32-bit Int Gate       1   0 Kernel                        
 0x99 0xffff816f5c28    32-bit Int Gate       1   0 Kernel                        
 0x9a 0xffff816f5c2c    32-bit Int Gate       1   0 Kernel                        
 0x9b 0xffff816f5c30    32-bit Int Gate       1   0 Kernel                        
 0x9c 0xffff816f5c34    32-bit Int Gate       1   0 Kernel                        
 0x9d 0xffff816f5c38    32-bit Int Gate       1   0 Kernel                        
 0x9e 0xffff816f5c40    32-bit Int Gate       1   0 Kernel                        
 0x9f 0xffff816f5c44    32-bit Int Gate       1   0 Kernel                        
 0xa0 0xffff816f5c48    32-bit Int Gate       1   0 Kernel                        
 0xa1 0xffff816f5c4c    32-bit Int Gate       1   0 Kernel                        
 0xa2 0xffff816f5c50    32-bit Int Gate       1   0 Kernel                        
 0xa3 0xffff816f5c54    32-bit Int Gate       1   0 Kernel                        
 0xa4 0xffff816f5c58    32-bit Int Gate       1   0 Kernel                        
 0xa5 0xffff816f5c60    32-bit Int Gate       1   0 Kernel                        
 0xa6 0xffff816f5c64    32-bit Int Gate       1   0 Kernel                        
 0xa7 0xffff816f5c68    32-bit Int Gate       1   0 Kernel                        
 0xa8 0xffff816f5c6c    32-bit Int Gate       1   0 Kernel                        
 0xa9 0xffff816f5c70    32-bit Int Gate       1   0 Kernel                        
 0xaa 0xffff816f5c74    32-bit Int Gate       1   0 Kernel                        
 0xab 0xffff816f5c78    32-bit Int Gate       1   0 Kernel                        
 0xac 0xffff816f5c80    32-bit Int Gate       1   0 Kernel                        
 0xad 0xffff816f5c84    32-bit Int Gate       1   0 Kernel                        
 0xae 0xffff816f5c88    32-bit Int Gate       1   0 Kernel                        
 0xaf 0xffff816f5c8c    32-bit Int Gate       1   0 Kernel                        
 0xb0 0xffff816f5c90    32-bit Int Gate       1   0 Kernel                        
 0xb1 0xffff816f5c94    32-bit Int Gate       1   0 Kernel                        
 0xb2 0xffff816f5c98    32-bit Int Gate       1   0 Kernel                        
 0xb3 0xffff816f5ca0    32-bit Int Gate       1   0 Kernel                        
 0xb4 0xffff816f5ca4    32-bit Int Gate       1   0 Kernel                        
 0xb5 0xffff816f5ca8    32-bit Int Gate       1   0 Kernel                        
 0xb6 0xffff816f5cac    32-bit Int Gate       1   0 Kernel                        
 0xb7 0xffff816f5cb0    32-bit Int Gate       1   0 Kernel                        
 0xb8 0xffff816f5cb4    32-bit Int Gate       1   0 Kernel                        
 0xb9 0xffff816f5cb8    32-bit Int Gate       1   0 Kernel                        
 0xba 0xffff816f5cc0    32-bit Int Gate       1   0 Kernel                        
 0xbb 0xffff816f5cc4    32-bit Int Gate       1   0 Kernel                        
 0xbc 0xffff816f5cc8    32-bit Int Gate       1   0 Kernel                        
 0xbd 0xffff816f5ccc    32-bit Int Gate       1   0 Kernel                        
 0xbe 0xffff816f5cd0    32-bit Int Gate       1   0 Kernel                        
 0xbf 0xffff816f5cd4    32-bit Int Gate       1   0 Kernel                        
 0xc0 0xffff816f5cd8    32-bit Int Gate       1   0 Kernel                        
 0xc1 0xffff816f5ce0    32-bit Int Gate       1   0 Kernel                        
 0xc2 0xffff816f5ce4    32-bit Int Gate       1   0 Kernel                        
 0xc3 0xffff816f5ce8    32-bit Int Gate       1   0 Kernel                        
 0xc4 0xffff816f5cec    32-bit Int Gate       1   0 Kernel                        
 0xc5 0xffff816f5cf0    32-bit Int Gate       1   0 Kernel                        
 0xc6 0xffff816f5cf4    32-bit Int Gate       1   0 Kernel                        
 0xc7 0xffff816f5cf8    32-bit Int Gate       1   0 Kernel                        
 0xc8 0xffff816f5d00    32-bit Int Gate       1   0 Kernel                        
 0xc9 0xffff816f5d04    32-bit Int Gate       1   0 Kernel                        
 0xca 0xffff816f5d08    32-bit Int Gate       1   0 Kernel                        
 0xcb 0xffff816f5d0c    32-bit Int Gate       1   0 Kernel                        
 0xcc 0xffff816f5d10    32-bit Int Gate       1   0 Kernel                        
 0xcd 0xffff816f5d14    32-bit Int Gate       1   0 Kernel                        
 0xce 0xffff816f5d18    32-bit Int Gate       1   0 Kernel                        
 0xcf 0xffff816f5d20    32-bit Int Gate       1   0 Kernel                        
 0xd0 0xffff816f5d24    32-bit Int Gate       1   0 Kernel                        
 0xd1 0xffff816f5d28    32-bit Int Gate       1   0 Kernel                        
 0xd2 0xffff816f5d2c    32-bit Int Gate       1   0 Kernel                        
 0xd3 0xffff816f5d30    32-bit Int Gate       1   0 Kernel                        
 0xd4 0xffff816f5d34    32-bit Int Gate       1   0 Kernel                        
 0xd5 0xffff816f5d38    32-bit Int Gate       1   0 Kernel                        
 0xd6 0xffff816f5d40    32-bit Int Gate       1   0 Kernel                        
 0xd7 0xffff816f5d44    32-bit Int Gate       1   0 Kernel                        
 0xd8 0xffff816f5d48    32-bit Int Gate       1   0 Kernel                        
 0xd9 0xffff816f5d4c    32-bit Int Gate       1   0 Kernel                        
 0xda 0xffff816f5d50    32-bit Int Gate       1   0 Kernel                        
 0xdb 0xffff816f5d54    32-bit Int Gate       1   0 Kernel                        
 0xdc 0xffff816f5d58    32-bit Int Gate       1   0 Kernel                        
 0xdd 0xffff816f5d60    32-bit Int Gate       1   0 Kernel                        
 0xde 0xffff816f5d64    32-bit Int Gate       1   0 Kernel                        
 0xdf 0xffff816f5d68    32-bit Int Gate       1   0 Kernel                        
 0xe0 0xffff816f5d6c    32-bit Int Gate       1   0 Kernel                        
 0xe1 0xffff816f5d70    32-bit Int Gate       1   0 Kernel                        
 0xe2 0xffff816f5d74    32-bit Int Gate       1   0 Kernel                        
 0xe3 0xffff816f5d78    32-bit Int Gate       1   0 Kernel                        
 0xe4 0xffff816f5d80    32-bit Int Gate       1   0 Kernel                        
 0xe5 0xffff816f5d84    32-bit Int Gate       1   0 Kernel                        
 0xe6 0xffff816f5d88    32-bit Int Gate       1   0 Kernel                        
 0xe7 0xffff816f5d8c    32-bit Int Gate       1   0 Kernel                        
 0xe8 0xffff816f5d90    32-bit Int Gate       1   0 Kernel                        
 0xe9 0xffff816f5d94    32-bit Int Gate       1   0 Kernel                        
 0xea 0xffff816f5d98    32-bit Int Gate       1   0 Kernel                        
 0xeb 0xffff816f5da0    32-bit Int Gate       1   0 Kernel                        
 0xec 0xffff816f5da4    32-bit Int Gate       1   0 Kernel                        
 0xed 0xffff816f5da8    32-bit Int Gate       1   0 Kernel                        
 0xee 0xffff816f5dac    32-bit Int Gate       1   0 Kernel                        
 0xef 0xffff816f5ef0    32-bit Int Gate       1   0 apic_timer_interrupt          
 0xf0 0xffff816f5db4    32-bit Int Gate       1   0 Kernel                        
 0xf1 0xffff816f5db8    32-bit Int Gate       1   0 Kernel                  
```
