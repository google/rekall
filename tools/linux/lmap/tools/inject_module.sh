#!/usr/bin/env bash
# Links two kernel modules together using .commend, .modinfo and __versions
# of the host module. The parasite module can not have init_module or
# exit_module, as this will result in a name clash.

PARASITE=$1
HOST=$2
echo "injecting $1 in $2"
strip --strip-unneeded -R .comment -R .modinfo -R .note.gnu.build-info -R .gnu.linkonce.this_module -R __versions $1
ld -r $1 $2 -o injected_$2
echo "done, result is injected_$2"
