"""Gathers all issued commands for zsh."""

from rekall.plugins.overlays import basic
from rekall.plugins.linux import heap_analysis


class Zsh(heap_analysis.HeapAnalysis):
    """Extracts the zsh command history, similar to the existing bash plugin."""

    __name = "zsh"

    def __init__(self, **kwargs):
        super(Zsh, self).__init__(**kwargs)
        self._zsh_profile = None


    def render(self, renderer):
        if self.session.profile.metadata("arch") == 'I386':
            self._zsh_profile = ZshProfile32(session=self.session)

        else:
            self._zsh_profile = ZshProfile64(session=self.session)

        chunk_size = self.get_aligned_size(self._zsh_profile.get_obj_size('histent'))

        for task in self.filter_processes():
            if self.init_for_task(task):

                chunks_dict = dict()

                data_offset = self._libc_profile.get_obj_offset("malloc_chunk", "fd")

                chunk_data_pointers = list()
                for chunk in self.get_all_allocated_chunks():
                    chunks_dict[chunk.v() + data_offset] = chunk
                    chunk_data_pointers.append(chunk.v() + data_offset)

                commands_dict = dict()

                valid_histentry = None

                # we first try to find a chunk that most probably contains a histent struct
                for chunk in self.get_all_allocated_chunks():

                    if not chunk.chunksize() == chunk_size:
                        continue

                    histent = self._zsh_profile.Object("histent",
                                                       offset=chunk.v()+data_offset,
                                                       vm=self.process_as)

                    ### we test if the current histent struct seems to be valid
                    # first test: do we know the chunks where relevant pointers point to
                    pointers = [histent.node.nam, histent.down, histent.up]
                    if not len(set(pointers) & set(chunk_data_pointers)) == len(pointers):
                        continue

                    # second test: points the previous/next histent entry to this histent entry?
                    if not histent.up.down == histent or not histent.down.up == histent:
                        continue


                    # we hopefully found one
                    valid_histentry = histent
                    break

                if valid_histentry:

                    self.session.logging.info(
                        "We probably found a valid histent chunk and now start walking.")

                    # entries are linked circular so walking in one direction should be sufficient
                    for histent in heap_analysis.iterate_through_linked_list(valid_histentry,
                                                                             lambda x: x.down):

                        command = ''

                        try:
                            command = chunks_dict[histent.node.nam.v()].to_string()
                            command = command[:command.index("\x00")]

                        except KeyError:
                            self.session.logging.warn("Unexpected error: chunk for given command-"
                                                      "reference does not seem to exist.")

                        except ValueError:
                            pass

                        if histent.stim == histent.ftim == 0 and command == '':
                            histent_vma = heap_analysis.get_vma_for_offset(self.vmas, histent.v())
                            if histent_vma not in self.heap_vmas:
                                # we most probably found the "curline" histent struct located in
                                # zsh's .bss section. as it doesn't contain an actual executed
                                # command, we are skipping it
                                continue

                        command_number = histent.histnum
                        start = self.profile.UnixTimeStamp(value=histent.stim)
                        end = self.profile.UnixTimeStamp(value=histent.ftim)
                        commands_dict[command_number] = [start, end, repr(command)]


                renderer.table_header([("PID", "pid", "6"),
                                       ("#", "commandnumber", "6"),
                                       ("Started", "started", "21"),
                                       ("Ended", "ended", "21"),
                                       ("Command", "command", "64")])

                for key, value in sorted(commands_dict.items()):
                    renderer.table_row(task.pid, key, *value)



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
