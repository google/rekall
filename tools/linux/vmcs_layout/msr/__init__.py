import struct
import glob


class Error(Exception):
    pass


def read_msr(msr_index, cpu_index=None):
    if cpu_index is not None:
        cpus = ["/dev/cpu/%d/msr" % cpu_index]
    else:
        cpus = sorted(list(glob.glob("/dev/cpu/*/msr")))

        if not cpus:
            raise Error("No CPUs found, did you run 'modprobe msr'?")

    for cpu_msr in cpus:
        try:
            cpu_msr_dev = open(cpu_msr, "rb")
        except IOError:
            raise Error(("Unable to open %s for writing. You need to be root."
                         % cpu_msr))
        cpu_msr_dev.seek(msr_index, 0)
        msr = cpu_msr_dev.read(8)
        msr_value = struct.unpack("<Q", msr)[0]
        cpu_msr_dev.close()
        yield msr_value


def write_msr(msr_index, msr_value, cpu_index=None):
    if cpu_index is not None:
        cpus = ["/dev/cpu/%d/msr" % cpu_index]
    else:
        cpus = sorted(list(glob.glob("/dev/cpu/*/msr")))

        if not cpus:
            raise Error("No CPUs found, did you run 'modprobe msr'?")

    for cpu_msr in cpus:
        try:
            cpu_msr_dev = open(cpu_msr, "wb")
        except IOError:
            raise Error(("Unable to open %s for writing. You need to be root."
                         % cpu_msr))
        cpu_msr_dev.seek(msr_index, 0)
        msr_value = struct.pack("<Q", msr_value)
        cpu_msr_dev.write(msr_value)
        cpu_msr_dev.close()
    return True

