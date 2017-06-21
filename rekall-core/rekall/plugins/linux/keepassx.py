"""Gathers password entries for keepassx.
   The retrieved content of those entries comprises the username, title, URL and Comment.
"""

import struct
from rekall.plugins.linux import heap_analysis


class Keepassx(heap_analysis.HeapAnalysis):
    """Gathers password entries for keepassx.
    The retrieved content of those entries comprises the username, title, URL and Comment.
    """

    __name = "keepassx"

    def render(self, renderer):
        for task in self.filter_processes():
            if self.init_for_task(task):

                chunks_dict = dict()

                data_offset = self._libc_profile.get_obj_offset("malloc_chunk", "fd")

                for chunk in self.get_all_allocated_chunks():
                    chunks_dict[chunk.v() + data_offset] = chunk


                renderer.table_header([("Entry", "entry", "6"),
                                       ("Title", "title", "29"),
                                       ("URL", "url", "28"),
                                       ("Username", "username", "28"),
                                       ("Comment", "comment", "44")])

                if self.session.profile.metadata("arch") == 'I386':
                    string_offset = 18
                    relevant_chunk_size = 96
                    pointer_offsets = [12, 16, 20, 36]

                else:
                    string_offset = 26
                    relevant_chunk_size = 192
                    pointer_offsets = [16, 24, 32, 64]

                entry_number = 1

                for chunk in chunks_dict.values():

                    try:

                        # chunks containing refs to password entries typically have a size of 96
                        # in the tested 32 bit environment
                        if not chunk.chunksize() == relevant_chunk_size:
                            continue

                        p_entry_data = chunk.to_string()

                        field_strings = []

                        # the pointers to title, username and so on are at these offsets
                        for i in pointer_offsets:
                            if self.session.profile.metadata("arch") == 'I386':
                                pointer = struct.unpack('I', p_entry_data[i:i+4])[0]
                            else:
                                pointer = struct.unpack('Q', p_entry_data[i:i+8])[0]

                            # if there is no chunk for the given pointer, we most probably
                            # have a wrong chunk. this will throw a KeyError exception
                            # and we proceed with the next chunk
                            curr_chunk_data = chunks_dict[pointer].to_string()

                            string_size = struct.unpack('I', curr_chunk_data[8:12])[0]
                            string_size *= 2

                            curr_string = curr_chunk_data[string_offset:string_offset+string_size]
                            curr_string = curr_string.decode('utf-16-le')

                            field_strings.append(repr(curr_string))


                        renderer.table_row(entry_number, *field_strings)
                        entry_number += 1

                    except (KeyError, UnicodeDecodeError):
                        # a password entry struct not containing a pointer to a chunk = out of scope
                        pass
