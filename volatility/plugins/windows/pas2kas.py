import volatility.conf as conf
import volatility.utils as utils
import volatility.commands as commands
import volatility.win32 as win32
import bisect
from volatility.cache import CacheDecorator


def parse_int(string):
   if string.startswith("0x"):
      return int(string, 16)
   return int(string)   

class pas2kas(commands.command):
    """ Convert a list of physical AS offsets (given on the command
    line) to a list of potential KVA addresses.
    """
    def __init__(self, *args):
        commands.command.__init__(self, *args)
        self._config.add_option('PID', short_option = 'p', default=None,
				cache_invalidator=False,
				help='Operate on this Process ID',
				action='store', type='int')

    def render_text(self, outfd, data):
        outfd.write("{0:10s} {1:10s}\n".format("Phys AS", "KAS"))
        for offset, result in data:
            outfd.write("0x{0:08x} 0x{1:08x}\n".format(offset, result))

    def coalesce_ranges(self, addr_space):
        """ Coalesce the page range given into large groups """
        last_va = 0
        last_pa = 0
        last_len = 0
        for va, length in addr_space.get_available_pages():
            pa = addr_space.vtop(va)
            if pa == None:
                continue

            ## This page is right after the last page in the range
            if (va - last_va) == (pa - last_pa):
                last_len += length
            else:
                if last_len>0:
                    yield (last_va, last_pa, last_len)

                last_va, last_pa, last_len = va, pa, length

        yield (last_va, last_pa, last_len)

    def get_task_as(self, kernel_addr_space):
        if self._config.PID:
            for t in win32.tasks.pslist(kernel_addr_space):
                if t.UniqueProcessId == self._config.PID:
                    return t.get_process_address_space()

            raise RuntimeError("Unable to locate pid %s" % self._config.PID)

        return kernel_addr_space

    ## This caches the mapping per each pid so we dont need to
    ## invalidate on different pids
    @CacheDecorator(lambda self: "address_space/memory_translation/"
                    "pas2kas/pid-{0}".format(self._config.PID))

    def get_ranges(self):
        addr_space = self.get_task_as(utils.load_as(self._config))

        ## Get the coalesced map:
        ranges = [ (va, pa, length) for va, pa, length in self.coalesce_ranges(addr_space) ]

        return ranges

    def calculate(self):
        ranges = self.get_ranges()

        ## Now for each Physical address, find all Virtual Addresses
        ## for it. We optimise by sorting on pa and use binary
        ## search via the bisect module to get O(log n) here.
        self._config.parse_options()
        for pa in self._config.args[1:]:
            needle = parse_int(pa)
            for va, pa, length in ranges:
                if needle >= pa and needle - pa < length:
                    yield (needle, va + (needle - pa))
