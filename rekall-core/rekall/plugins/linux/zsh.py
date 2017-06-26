#  Extracts Zsh command history
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

"""Gathers all issued commands for zsh."""

from rekall.plugins.overlays import basic
from rekall.plugins.linux import heap_analysis


class Zsh(heap_analysis.HeapAnalysis):
    """Extracts the zsh command history, similar to the existing bash plugin.
    """

    __name = "zsh"

    table_header = [
        dict(name="", cname="divider", type="Divider"),
        dict(name="task", hidden=True),
        dict(name="counter", width=8),
        dict(name="started", width=24),
        dict(name="ended", width=24),
        dict(name="command")
    ]

    def __init__(self, **kwargs):
        super(Zsh, self).__init__(**kwargs)
        self._zsh_profile = None


    def collect(self):
        if self.session.profile.metadata("arch") == 'AMD64':
            self._zsh_profile = ZshProfile64(session=self.session)

        else:
            # default/fallback profile
            self._zsh_profile = ZshProfile32(session=self.session)

        chunk_size = self.get_aligned_size(
            self._zsh_profile.get_obj_size('histent'))

        for task in self.filter_processes():
            if self.init_for_task(task):

                yield dict(divider="Task: %s (%s)" % (task.name,
                                                      task.pid))

                chunks_dict = dict()

                data_offset = self.profile.get_obj_offset("malloc_chunk", "fd")

                chunk_data_pointers = list()
                for chunk in self.get_all_allocated_chunks():
                    chunks_dict[chunk.v() + data_offset] = chunk
                    chunk_data_pointers.append(chunk.v() + data_offset)

                commands_dict = dict()

                valid_histentry = None

                # we first try to find a chunk that most probably contains a
                # histent struct
                for chunk in self.get_all_allocated_chunks():

                    if not chunk.chunksize() == chunk_size:
                        continue

                    histent = self._zsh_profile.histent(
                        offset=chunk.v()+data_offset, vm=self.process_as)

                    # we test if the current histent struct seems to be valid
                    # first test: do we know the chunks where relevant
                    # pointers point to
                    pointers = [histent.node.nam, histent.down, histent.up]
                    if not len(set(pointers) & set(chunk_data_pointers)) \
                            == len(pointers):
                        continue

                    # second test: points the previous/next histent entry to
                    # this histent entry?
                    if not histent.up.down == histent or not histent.down.up \
                            == histent:
                        continue

                    # we hopefully found one
                    valid_histentry = histent
                    break

                if valid_histentry:
                    self.session.logging.info(
                        "We probably found a valid histent chunk and now "
                        "start walking.")

                    # entries are linked circular so walking in one direction
                    # should be sufficient
                    for histent in valid_histentry.walk_list('down'):

                        command = ''

                        try:
                            command = chunks_dict[histent.node.nam.v()]
                            command = command.to_string()
                            command = command[:command.index("\x00")]

                        except KeyError:
                            self.session.logging.warn(
                                "Unexpected error: chunk for given "
                                "command-reference does not seem to exist.")

                        except ValueError:
                            pass

                        if histent.stim == histent.ftim == 0 and command == '':
                            histent_vma = heap_analysis.get_vma_for_offset(
                                self.vmas, histent.v())

                            if histent_vma not in self.heap_vmas:
                                # we most probably found the "curline" histent
                                # struct located in zsh's .bss section. as it
                                # doesn't contain an actual executed command,
                                # we are skipping it
                                continue

                        command_number = histent.histnum
                        start = self.profile.UnixTimeStamp(value=histent.stim)
                        end = self.profile.UnixTimeStamp(value=histent.ftim)
                        commands_dict[command_number] = [start,
                                                         end,
                                                         repr(command)]


                for key, value in sorted(commands_dict.items()):
                    yield dict(task=task, counter=key, started=value[0],
                               ended=value[1], command=value[2])



class ZshProfile32(basic.Profile32Bits, basic.BasicClasses):
    """Profile to parse internal zsh data structures."""

    __abstract = True

    # types come from zsh's zsh.h
    zsh_vtype_32 = {
        "histent": [48, {
            "down": [16, ["Pointer", {
                "target": "histent"
            }]],
            "ftim": [28, ["long int"]],
            "histnum": [40, ["long long int"]],
            "node": [0, ["hashnode"]],
            "nwords": [36, ["int"]],
            "stim": [24, ["long int"]],
            "up": [12, ["Pointer", {
                "target": "histent"
            }]],
            "words": [32, ["Pointer", {
                "target": "short int"
            }]],
            "zle_text": [20, ["Pointer", {
                "target": "char"
            }]]
        }],
        "hashnode": [12, {
            "flags": [8, ["int"]],
            "nam": [4, ["Pointer", {
                "target": "char"
            }]],
            "next": [0, ["Pointer", {
                "target": "hashnode"
            }]]
        }]
    }

    def __init__(self, **kwargs):
        super(ZshProfile32, self).__init__(**kwargs)
        self.add_types(self.zsh_vtype_32)



class ZshProfile64(basic.ProfileLP64, basic.BasicClasses):
    """Profile to parse internal zsh data structures."""

    __abstract = True

    # types come from zsh's zsh.h
    zsh_vtype_64 = {
        "histent": [88, {
            "down": [32, ["Pointer", {
                "target": "histent"
            }]],
            "ftim": [56, ["long int"]],
            "histnum": [80, ["long int"]],
            "node": [0, ["hashnode"]],
            "nwords": [72, ["int"]],
            "stim": [48, ["long int"]],
            "up": [24, ["Pointer", {
                "target": "histent"
            }]],
            "words": [64, ["Pointer", {
                "target": "short int"
            }]],
            "zle_text": [40, ["Pointer", {
                "target": "char"
            }]]
        }],
        "hashnode": [24, {
            "flags": [16, ["int"]],
            "nam": [8, ["Pointer", {
                "target": "char"
            }]],
            "next": [0, ["Pointer", {
                "target": "hashnode"
            }]]
        }]
    }

    def __init__(self, **kwargs):
        super(ZshProfile64, self).__init__(**kwargs)
        self.add_types(self.zsh_vtype_64)
