#!/usr/bin/env python
# Rekall Memory Forensics
# Copyright 2016 Google Inc. All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

"""This script unpacks a kernel debug kit DMG, finds and extracts the correct
mach kernel binary (production kernel with debug DWARF stream) and dumps it
to stdout.

Unlike other vendors, Apple doesn't provide a standard way to request debug
symbols for their software. Instead, they release the so called Kernel Debug
Kits, which are DMGs with installer packages in them that install a variety
of kernel builds, headers and scripts onto a system for kernel extension
debuging.

The only file from the lot we actually need is the production kernel build
with the DWARF stream left intact (it's stripped out of the version that ships).

In contours, this is where the file is:
 - KernelDebugKit.dmg (top level DMG)
   - KernelDebugKit.pkg (cpio archive)
     - Payload (pbxz-compressed stream)
       - unnamed cpio archive inside the stream
         - (at a nested path) kernel.dSYM (bundle)
           - kernel binary
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

import argparse
import contextlib
import os
import re
import shutil
import subprocess
import struct
import sys
import tempfile


KDBGKIT_PKG_NAME = re.compile(r"^.*?KernelDebug.*?\.pkg$")

DEVNULL = open(os.devnull, "wb")

PBZX_MAGIC = "\x70\x62\x7a\x78"
XZ_MAGIC = "\xfd7zXZ\x00"
BZIP2_MAGIC = "BZ"

PBX_BLOCK_SIZE = 0x1000000
IO_CHUNKSIZE = 0x1000

PAYLOAD_SIGNATURES = (PBZX_MAGIC, BZIP2_MAGIC)

# Functions prefixed with 'run_' or 'create_, as well as main() have side
# effects. Everything else should be OK.


def hdiutil_attach(path, at_path):
    return ["hdiutil", "attach", path,
            "-mountpoint", at_path,
            "-noautoopen"]


def hdiutil_detach(path):
    return ["hdiutil", "detach", path]


def tar_unpack(path, target_dir):
    return ["tar", "-xf", path, "-C", target_dir]


def run_mount_kdbg(path):
    """Mount DMG at 'path' and return the mountpoint.

    Raises:
        IOError at first sign of trouble.
    """
    if not os.path.isfile(path):
        raise IOError

    at_path = os.path.join("/", "Volumes", "kdbg_kit")

    result = subprocess.call(hdiutil_attach(path, at_path), stderr=DEVNULL,
                             stdout=DEVNULL)

    if result != 0:
        raise IOError("%r returned %d" % (hdiutil_attach(path), result))

    return at_path


def run_umount(mountpoint):
    """Unmount 'mountpoint'."""
    result = subprocess.call(hdiutil_detach(mountpoint), stderr=DEVNULL,
                             stdout=DEVNULL)

    if result != 0:
        raise IOError("%r returned %d" % (hdiutil_detach(mountpoint)), result)


@contextlib.contextmanager
def run_xz_decompress(stdout, stderr=None):
    """Run xz --decompress and return a contextmanager object for the proc."""
    xz = None
    try:
        xz = subprocess.Popen(["xz", "--decompress", "--stdout"],
                              stdin=subprocess.PIPE, stdout=stdout,
                              stderr=stderr)
        yield xz
    finally:
        if not xz:
            raise OSError("You must have an 'xz' binary in PATH.")

        xz.stdin.close()
        result = xz.wait()

        if result != 0:
            raise IOError("xz --decompress returned %d." % result)


def find_pkg_file(volume_path):
    """Find the kernel debug kit file in 'volume_path'."""
    for root, _, files in os.walk(volume_path):
        for file in files:
            if KDBGKIT_PKG_NAME.match(file):
                return os.path.join(root, file)

    raise OSError("Couldn't find debug kit pkg.")


def find_payload_file(root_path):
    """Find the Payload pbzx/bzip2 file in 'root_path'."""
    sig_max_length = max(len(x) for x in PAYLOAD_SIGNATURES)

    for root, _, files in os.walk(root_path):
        for file in files:
            if file == "Payload":
                candidate = os.path.join(root, file)
                with open(candidate, "rb") as fd:
                    head = fd.read(sig_max_length)
                    for sig in PAYLOAD_SIGNATURES:
                        if head.startswith(sig):
                            return candidate, sig

                return candidate

    raise OSError("Couldn't find Payload file.")


def find_production_kernel_dsym(root_path):
    """Find the kernel.dSYM for the production kernel."""
    for root, dirs, _ in os.walk(root_path):
        for dir_ in dirs:
            if dir_.lower().endswith("kernel.dsym"):
                new_root = os.path.join(root, dir_)
                try:
                    return find_kernel_binary(new_root)
                except OSError:
                    continue

    raise OSError("Couldn't find the kernel dsym.")


def find_kernel_binary(root_path):
    """Find the right kernel binary in 'root_path'."""
    for root, _, files in os.walk(root_path):
        for file in files:
            if file.lower().endswith("kernel"):
                return os.path.join(root, file)

    raise OSError("Couldn't find the kernel binary.")


def run_tar_unpack(path, target_dir):
    """Unpack tar archive at 'path' into 'target_dir'."""
    result = subprocess.call(tar_unpack(path, target_dir),
                             stdout=DEVNULL)

    if result != 0:
        raise IOError("%r returned %d" %
                      (tar_unpack(path, target_dir)))


def decode_payload(payload_path, payload_type, target_path):
    if payload_type == PBZX_MAGIC:
        with open(payload_path, "rb") as in_fd:
            with open(target_path, "wb") as out_fd:
                decode_pbx_payload(in_fd, out_fd)
    elif payload_type == BZIP2_MAGIC:
        run_decode_bzip2(payload_path, target_path)
    else:
        raise OSError("Unknown Payload file format.")


def run_decode_bzip2(path, out_path):
    # bzip2 will read data on its own, but it needs help writing output.
    with open(out_path, "wb") as out_fd:
        bzip = subprocess.Popen(["bzip2", "-d", "-k", "-c", path],
                                stdout=out_fd)
        result = bzip.wait()
        if result != 0:
            raise IOError("bzip2 returned %d." % result)


def decode_pbx_payload(in_fd, out_fd):
    """Read PBZX stream on 'in_fd' and write a CPIO archive to 'out_fd'."""
    # The payload file is PBX-packed. This code is roughly based on this:
    # https://gist.github.com/bruienne/029494bbcfb358098b41.

    magic = in_fd.read(4)
    if magic != PBZX_MAGIC:
        raise IOError("File is not a PBZX file.")

    # Flags are an uint_64.
    flags_bytes = in_fd.read(8)
    flags = struct.unpack(">Q", flags_bytes)[0]

    while flags & (1 << 24):
        # For some idiotic reason, PBZX blocks contain a flag that tells you
        # whether they're the last block. So if the previous block didn't have
        # the "more blocks" flag set we can terminate next time.
        #
        # My guess is that someone didn't like do-while loops, which is why we
        # ended up with this file format.
        flags_bytes = in_fd.read(8)
        flags = struct.unpack(">Q", flags_bytes)[0]

        # Next 8 bytes are the number of bytes that follow. If this number
        # is the same as the size of the decompressed block then the block is
        # not compressed (duh).
        length_bytes = in_fd.read(8)
        length = struct.unpack(">Q", length_bytes)[0]

        sys.stderr.write("Decompressing pbzx block @0x%x."
                         " Compressed size: %lu; flags: 0x%x.\n"
                         % (in_fd.tell() - 16, length, flags))

        if length == PBX_BLOCK_SIZE:
            # Block not compressed. Copy raw data.
            remaining = length
            while remaining:
                count = max(IO_CHUNKSIZE, remaining)
                data = in_fd.read(IO_CHUNKSIZE)
                out_fd.write(data)
                remaining -= count
        else:
            # Block is compressed (compressed size < expected block size).
            # The only compression we know about is XZ.
            magic = in_fd.read(len(XZ_MAGIC))
            if magic != XZ_MAGIC:
                raise IOError("PBX file block @0x%x doesn't have a XAR header."
                              " (Got %r, expected %r)"
                              % (in_fd.tell() - len(XZ_MAGIC), magic, XZ_MAGIC))

            # This is where it gets a little ghetto - we don't have a nice way
            # of decompressing xz without external dependencies, so we pipe
            # the block to xz --decompress. Don't look at me like that.
            with run_xz_decompress(stdout=out_fd) as xz:
                # xz --decompress expects an XZ file, including headers.
                xz.stdin.write(magic)
                # Write to xz's input in chunks, because the file could be
                # large-ish.
                remaining = length - len(magic)
                while remaining:
                    count = max(IO_CHUNKSIZE, remaining)
                    data = in_fd.read(count)
                    xz.stdin.write(data)
                    remaining -= count


def create_unpacked_kdbg(volume_path, target_dir):
    """Search 'volume_path' for the debug kit file and unpack it into temp.

    Arguments:
        volume_path: Where the debug kit DMG is mounted.
        target_dir: Temp directory where the contents will be unpacked into.

    Raises:
        IOError or OSError on failure.

    Returns:
        Nothing.
    """
    # Copy and untar the debug kit from the mounted Volume.
    src_path = find_pkg_file(volume_path)
    pkg_path = os.path.join(target_dir, "debug_kit.pkg")
    shutil.copy(src_path, pkg_path)

    sys.stderr.write("Package file copied from %s to %s.\n" %
                     (src_path, pkg_path))

    run_tar_unpack(pkg_path, target_dir)

    # Now find the compressed Payload file and unpack that, using magic.
    payload_path, payload_type = find_payload_file(target_dir)
    sys.stderr.write("Payload file is now at %s.\n" % payload_path)
    decoded_payload_path = os.path.join(target_dir, "Payload.raw")

    decode_payload(payload_path=payload_path, payload_type=payload_type,
                   target_path=decoded_payload_path)

    # The decoded payload file is a CPIO archive, which we can unpack with tar.
    run_tar_unpack(decoded_payload_path, target_dir)


def main():
    parser = argparse.ArgumentParser(
        description=("Extract the kernel binary with debug DWARF from the "
                     "kernel debug kit at 'path' and dump it to stdout."))
    parser.add_argument("path", help="Path to the DMG.")
    args = parser.parse_args()

    try:
        tempdir = tempfile.mkdtemp()
        sys.stderr.write("Tempdir at %s.\n" % tempdir)

        mountpoint = run_mount_kdbg(args.path)
        sys.stderr.write("Debug kit mounted at %s.\n" % mountpoint)

        create_unpacked_kdbg(mountpoint, tempdir)
        sys.stderr.write("Kernel Debug Kit unpacked into tempdir %s.\n" %
                         tempdir)

        kernel_path = find_production_kernel_dsym(tempdir)
        sys.stderr.write("Kernel binary found at %s.\n" % kernel_path)

        with open(kernel_path, "rb") as fd:
            data = fd.read(IO_CHUNKSIZE)

            while data:
                sys.stdout.write(data)
                data = fd.read(IO_CHUNKSIZE)
    finally:
        sys.stderr.write("Unmounting %s.\n" % mountpoint)
        run_umount(mountpoint)

        sys.stderr.write("Destroying %s.\n" % tempdir)
        shutil.rmtree(tempdir)


if __name__ == "__main__":
    main()
