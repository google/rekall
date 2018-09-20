#  Calculates KASLR shift(s)
#
#    Copyright (c) 2018, Frank Block, ERNW GmbH <fblock@ernw.de>
#
#       All rights reserved.
#
#       Redistribution and use in source and binary forms, with or without modification,
#       are permitted provided that the following conditions are met:
#
#       * Redistributions of source code must retain the above copyright notice, this
#         list of conditions and the following disclaimer.
#       * Redistributions in binary form must reproduce the above copyright notice,
#         this list of conditions and the following disclaimer in the documentation
#         and/or other materials provided with the distribution.
#       * The names of the contributors may not be used to endorse or promote products
#         derived from this software without specific prior written permission.
#
#       THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#       AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#       IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#       ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
#       LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#       DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#       SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#       CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#       OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#       OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""
Mainly based on the great blogpost series by bneuburg:
    https://bneuburg.github.io/volatility/kaslr/2017/04/26/KASLR1.html
    https://bneuburg.github.io/volatility/kaslr/2017/05/05/KASLR2.html
    https://bneuburg.github.io/volatility/kaslr/2017/05/16/KASLR3.html
and on the modifications included in Volatility:
    https://github.com/volatilityfoundation/volatility/commit/3619c8a32f5b2f552bbc4a8464a6ea768de48423

Tested on x86 and x86_64 for NOKASLR and KASLR 1st and 2nd generation.
"""

__author__ = "Frank Block <fblock@ernw.de>"

from rekall import scan
from rekall import obj
from rekall.plugins.linux import common
import struct


class SwapperScanner(scan.BaseScanner):

    checks = [("StringCheck", dict(needle=b"swapper/0\x00"))]


class FindKaslr(common.AbstractLinuxCommandPlugin):

    name = "find_kaslr"

    __args = [
        dict(name='scan_whole_physical_space', type="Boolean", default=False,
             help='Normally, we scan at max only the first gigabyte of '
                  'memory, which should be fine as the linux kernel and its '
                  'data is normally located in the beginning of the physical '
                  'memory space.')
    ]

    table_header = [
        dict(name="physical_shift", width=16, style="address"),
        dict(name="virtual_shift", width=16, style="address"),
        dict(name="kernel_slide", width=16, style="address"),
        dict(name="page_offset", width=16, style="address"),
        dict(name="DTB", width=16, style="address"),
        dict(name="Valid", width=16),
        dict(name="comment", width=48)
    ]

    def collect(self):
        shifts  = [0xffff80000000]
        if self.session.profile.metadata("arch") == 'AMD64':
            pass

        elif self.session.profile.metadata("arch") == 'I386':
            shifts = [0xc0000000]

        else:
            self.session.error.logging.error(
                "Unsupported architecture.")
            return

        physical_shift = 0
        virtual_shift = 0
        kernel_slide = 0
        page_offset = 0

        comm_offset = self.profile.get_obj_offset('task_struct', 'comm')
        pid_offset = self.profile.get_obj_offset('task_struct', 'pid')
        files_offset = self.profile.get_obj_offset('task_struct', 'files')
        pas = self.session.physical_address_space

        pointer_size = self.profile.get_obj_size("Pointer")
        fmt = 'I' if pointer_size == 4 else 'Q'

        init_task_address = self.profile.get_constant('init_task',
                                                      is_address=True)
        init_task_offset = init_task_address - shifts[0]
        init_files_address = self.profile.get_constant('init_files',
                                                       is_address=True)
        init_files_offset = init_files_address - shifts[0]
        pgt_virt_address = (
            self.profile.get_constant("init_level4_pgt", is_address=True) or
            self.profile.get_constant("init_top_pgt", is_address=True))

        scanner = SwapperScanner(session=self.session, profile=self.profile,
            address_space=self.session.physical_address_space)

        valid_dtb_value = None

        last_address = self.session.physical_address_space.end() if \
                self.plugin_args.scan_whole_physical_space else 0x40000000

        for swapper_offset in scanner.scan(0, last_address):
            comment = ''
            self.session.logging.debug("Found swapper comm offset at: 0x{:x}"
                .format(swapper_offset))

            potential_physical_shift = \
                swapper_offset - comm_offset - init_task_offset

            # this check should strip most false positive hits for swapper:
            # proceed only if the calculated shift is aligned
            if potential_physical_shift % 0x100000 != 0:
                continue
            
            # we expect the pid value to be 0
            pid_value = b'\x00' * self.profile.task_struct().pid.obj_size
            if pas.read(swapper_offset-comm_offset+pid_offset, 4) != pid_value:
                continue

            # we probably found the swapper task
            self.session.logging.debug(
                "Probably found swapper task_struct at: 0x{:x}"
                .format(swapper_offset-comm_offset))
            self.session.logging.debug("Potential physical shift is: 0x{:x}"
                .format(potential_physical_shift))

            swapper_task_struct = swapper_offset - comm_offset
            files_address = swapper_task_struct + files_offset
            files_buf  = pas.read(files_address, pointer_size)
            files_value = struct.unpack(fmt, files_buf)[0]
            self.session.logging.debug(
                "Extracted files address from swapper task_struct: 0x{:x}"
                .format(files_value))
            files_value = obj.Pointer.integer_to_address(files_value)
            virtual_shift = files_value - shifts[0] - init_files_offset

            # now we can calculate page_offset
            physical_shift = potential_physical_shift
            kernel_slide = virtual_shift
            page_offset = shifts[0] + kernel_slide - physical_shift

            if physical_shift == virtual_shift == 0:
                self.session.logging.info(
                    "This dump doesn't seem to use KASLR.")
                comment = "No KASLR"

            else:
                # we are setting those values in order to verify any
                # potentially found DTB in the next step
                self.session.logging.debug(
                    "Adjusting Kernel Image Base to 0x{:x}"
                    .format(kernel_slide))
                self.session.profile.image_base = kernel_slide
                self.session.logging.debug(
                    "Setting page_offset to 0x{:x}".format(page_offset))
                self.session.SetParameter("page_offset", page_offset)

            dtb_verifier = self.session.plugins.find_dtb(session=self.session)
            for dtb in dtb_verifier.dtb_hits():
                if comment != "No KASLR":
                    comment = ''
                valid_dtb = False
                
                try:
                    valid_dtb = dtb_verifier.VerifyHit(dtb) != None
                except TypeError:
                    pass

                if valid_dtb:
                    valid_dtb_value = dtb
                    if not comment:
                        comment = \
                            "Use cmd line options --dtb and --kernel_slide."

                yield dict(physical_shift=physical_shift,
                           virtual_shift=virtual_shift,
                           kernel_slide=kernel_slide,
                           page_offset=page_offset,
                           DTB=dtb,
                           Valid=valid_dtb,
                           comment=comment)

        # only done to prevent an exception on multiple hits, where the last
        # hit is no valid dtb value
        self.session.SetParameter("dtb", valid_dtb_value)
