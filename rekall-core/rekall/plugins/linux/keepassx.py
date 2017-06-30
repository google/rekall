#  Gathers information about password entries for keepassx
#
#    Copyright (c) 2017, Frank Block, ERNW GmbH <fblock@ernw.de>
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

"""Gathers information about password entries for keepassx.
   The retrieved content of those entries comprises the username, title, URL
   and Comment.
"""

import struct
from rekall.plugins.linux import heap_analysis


class Keepassx(heap_analysis.HeapAnalysis):
    """Gathers password entries for keepassx.
    The retrieved content of those entries comprises the username, title, URL
    and Comment."""

    __name = "keepassx"

    table_header = [
        dict(name="", cname="divider", type="Divider"),
        dict(name="task", hidden=True),
        dict(name="entry", width=6),
        dict(name="title", width=26),
        dict(name="url", width=28),
        dict(name="username", width=28),
        dict(name="comment", width=44)
    ]


    def collect(self):
        for task in self.filter_processes():
            if self.init_for_task(task):

                yield dict(divider="Task: %s (%s)" % (task.name,
                                                      task.pid))

                chunks_dict = dict()

                data_offset = self.profile.get_obj_offset("malloc_chunk", "fd")

                for chunk in self.get_all_allocated_chunks():
                    chunks_dict[chunk.v() + data_offset] = chunk

                if self.session.profile.metadata("arch") == 'AMD64':
                    string_offset = 26
                    relevant_chunk_size = 192
                    pointer_offsets = [16, 24, 32, 64]

                else:
                    string_offset = 18
                    relevant_chunk_size = 96
                    pointer_offsets = [12, 16, 20, 36]

                entry_number = 1

                for chunk in chunks_dict.values():

                    try:
                        # chunks containing refs to password entries typically
                        # have a size of 96 in the tested 32 bit environment
                        if not chunk.chunksize() == relevant_chunk_size:
                            continue

                        p_entry_data = chunk.to_string()

                        field_strings = []

                        # the pointers to title, username and so on are at
                        # these offsets
                        for i in pointer_offsets:
                            if self.session.profile.metadata("arch") == 'I386':
                                pointer = struct.unpack('I',
                                                        p_entry_data[i:i+4])[0]
                            else:
                                pointer = struct.unpack('Q',
                                                        p_entry_data[i:i+8])[0]

                            # if there is no chunk for the given pointer, we
                            # most probably have a wrong chunk. this will
                            # throw a KeyError exception and we proceed with
                            # the next chunk
                            curr_chunk_data = chunks_dict[pointer].to_string()

                            string_size = struct.unpack(
                                'I', curr_chunk_data[8:12])[0]

                            string_size *= 2

                            curr_string = curr_chunk_data[
                                string_offset:string_offset+string_size]

                            curr_string = curr_string.decode('utf-16-le')

                            field_strings.append(repr(curr_string))


                        yield dict(task=task, entry=entry_number,
                                   title=field_strings[0],
                                   url=field_strings[1],
                                   username=field_strings[2],
                                   comment=field_strings[3])

                        entry_number += 1

                    except (KeyError, UnicodeDecodeError):
                        # a password entry struct not containing a pointer to
                        # a chunk => out of scope
                        pass
