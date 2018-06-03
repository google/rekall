#  Extracts Zsh command history
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

"""Gathers all issued commands for zsh."""

__author__ = "Frank Block <fblock@ernw.de>"

from rekall.plugins.overlays import basic
from rekall.plugins.linux import heap_analysis
import re


class Zsh(heap_analysis.HeapAnalysis):
    """Extracts the zsh command history, similar to the existing bash plugin.
    """

    name = "zsh"

    table_header = [
        dict(name="divider", type="Divider"),
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
        for task in self.filter_processes():
            if not self.init_for_task(task):
                continue

            # as there might be different zsh versions running, we verify this
            # for each process
            zsh_version_regex = "/zsh/(\d+)\.(\d+)[0-9\.]*/"

            # fallback version
            zsh_version = '52'

            vma_name = heap_analysis.get_vma_name_for_regex(self.vmas,
                                                            zsh_version_regex)

            major_version = minor_version = None

            if vma_name:
                match = re.search(zsh_version_regex, vma_name, re.IGNORECASE)
                if match and len(match.groups()) == 2:
                    major_version = int(match.group(1))
                    minor_version = int(match.group(2))
                    zsh_version = str(major_version) + str(minor_version)

            if self.session.profile.metadata("arch") == 'AMD64':
                self._zsh_profile = ZshProfile64(version=zsh_version,
                                                 session=self.session)

            else:
                # default/fallback profile
                self._zsh_profile = ZshProfile32(version=zsh_version,
                                                 session=self.session)

            chunk_size = self._zsh_profile.get_obj_size('histent')
            chunk_size = self.get_aligned_size(chunk_size)

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
                        command = command.get_chunk_data()
                        command = command[:command.index(b'\x00')]
                        command = command.decode('utf-8')

                    except KeyError:
                        self.session.logging.warn(
                            "Unexpected error: chunk for given "
                            "command-reference does not seem to exist.")

                    except ValueError:
                        command = command.get_chunk_data()

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
    histent_52_vtype_32 = {
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
        }]
    }

    hashnode_52_vtype_32 = {
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

    version_dict = {
        '52': [histent_52_vtype_32, hashnode_52_vtype_32]
    }

    def __init__(self, version=None, **kwargs):
        super(ZshProfile32, self).__init__(**kwargs)
        profile = dict()

        # the only relevant/implemented version currently is 5.2 (structs for
        # versions > 5.2 didn't change yet, at least not until 5.4.2)
        if version:
            try:
                self.session.logging.info(
                    "We are using I386 Zsh profile version {:s}"
                    .format(version))

                for vtypes in self.version_dict[version]:
                    profile.update(vtypes)

            except KeyError:
                self.session.logging.info(
                    "The given version string: {:s} is not in our dict. "
                    .format(version))

        if not profile:
            # the default profile to use
            self.session.logging.info(
                "We are using the I386 default Zsh profile version 5.2")

            for vtypes in self.version_dict['52']:
                profile.update(vtypes)

        self.add_types(profile)


class ZshProfile64(basic.ProfileLP64, basic.BasicClasses):
    """Profile to parse internal zsh data structures."""

    __abstract = True

    # types come from zsh's zsh.h
    histent_52_vtype_64 = {
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
        }]
    }

    hashnode_52_vtype_64 = {
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

    version_dict = {
        '52': [histent_52_vtype_64, hashnode_52_vtype_64]
    }

    def __init__(self, version=None, **kwargs):
        super(ZshProfile64, self).__init__(**kwargs)
        profile = dict()

        # the only relevant/implemented version currently is 5.2 (structs for
        # versions > 5.2 didn't change yet, at least not until 5.4.2)
        if version:
            try:
                self.session.logging.info(
                    "We are using AMD64 Zsh profile version {:s}"
                    .format(version))

                for vtypes in self.version_dict[version]:
                    profile.update(vtypes)

            except KeyError:
                self.session.logging.info(
                    "The given version string: {:s} is not in our dict. "
                    .format(version))

        if not profile:
            # the default profile to use
            self.session.logging.info(
                "We are using the AMD64 default Zsh profile version 5.2")

            for vtypes in self.version_dict['52']:
                profile.update(vtypes)

        self.add_types(profile)
