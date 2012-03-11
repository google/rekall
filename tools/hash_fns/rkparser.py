import sys, os

import elf, vmem_getbytes

reader     = vmem_getbytes.get_bytes()

def hash_syms(elf):
    
    elf_syms = elf.elf_symbols.symbols
    
    for sym in elf_syms:

        addr   = sym.val 
        size   = sym.size     
        name   = sym.name
        digest = sym.digest

        print "%s | %d | %d | %s | %s" % (name, addr, size, digest, sym.althash)
        
def main():
    
    vmlinux = sys.argv[1]
    
    elfObj = elf.Elf(vmlinux)
    mem_syms = hash_syms(elfObj)
    
if __name__ == "__main__":
    main()
        
