# Rekall Memory Forensics
#
# Copyright 2013 Google Inc. All Rights Reserved.
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

WinPMEM - a kernel mode driver for gaining access to physical memory.
Version 1.6.0

Michael Cohen <scudette@google.com>

This directory contains two binaries:

winpmem_1.6.0.exe: The officially supported winpmem binary memory imager. This
contains signed drivers for loading into 64 bit windows versions. The drivers
support only read mode for forensic analysis. Write support is disabled.

winpmem_write_1.6.0.exe: This is a binary with test signed drivers that also have
write support enabled. These will not load on a regular windows machine! In
order to use these drivers you will need to enable test mode signing in your
kernel:

Bcdedit.exe -set TESTSIGNING ON

and reboot.

Also included are the raw signed drivers. These are useful for integrating into
another program (see rekall/tools/windows/winpmem/winpmem.py).

All binaries in this directory are also stored in a single Zip file: 
winpmem_1.6.0.zip.

