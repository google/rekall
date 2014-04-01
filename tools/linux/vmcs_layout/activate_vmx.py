"""Sets the processors to +VME,+LOCK,-SMM to be able to run vmcs_layout."""

import logging
import msr
import sys

MSR_IDX = 0x3A

LOCK_BIT_MASK = 0x1
VME_BIT_MASK = 0x4
SMM_BIT_MASK = 0x2


if __name__ == "__main__":
    all_cpus_ready = True

    if len(sys.argv) > 1 and sys.argv[1] == "-v":
        logging.basicConfig(level=logging.DEBUG)

    for i, msr_value in enumerate(msr.read_msr(MSR_IDX)):
        logging.debug("CPU %d // MSR 0x%X = %016X",i, MSR_IDX, msr_value)
        dont_update = 0
        lock_on = False
        vme_on = False
        smm_on = False

        if msr_value & LOCK_BIT_MASK:
            lock_on = True
        else:
            msr_value |= LOCK_BIT_MASK

        if msr_value & VME_BIT_MASK:
            vme_on = True
        else:
            msr_value |= VME_BIT_MASK

        if msr_value & SMM_BIT_MASK:
            # Disable SMM VME
            msr_value &= (0xFFFFFFFFFFFFFFFF & ~SMM_BIT_MASK)

        if lock_on:
            if vme_on:
                print "CPU %d is VME-ready" % i
            else:
                print ("CPU %d is not VME-ready and cannot activate it.\n"
                       "Please check your BIOS settings.")
                all_cpus_ready = False
        else:
            print "CPU %d is NOT ready" % i
            print "Updating MSR 0x%X on CPU %d: %016X" % (MSR_IDX, i, msr_value)
            msr.write_msr(MSR_IDX, msr_value, cpu_index=i)

    if all_cpus_ready:
        print ("All CPUs ready, you can now do 'make && insmod "
               "vmcs_layout.ko && rmmod vmcs_layout'.")
