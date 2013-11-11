import sys, os, struct

import elf, vmem_getbytes

reader     = vmem_getbytes.get_bytes()

def hash_syms(elf):
    
    elf_syms = elf.elf_symbols.symbols    

    taddr    = 0x465000
    numbytes = 256 * 8

    table = elf.elf_symbols.filedata[taddr : taddr + numbytes]

    for idx in xrange(0, numbytes, 8):

        b = table[idx:idx+8]

        print b
    

def main():
    
    vmlinux = sys.argv[1]
    
    elfObj = elf.Elf(vmlinux)
    hash_syms(elfObj)   
 
if __name__ == "__main__":
    main()
        
