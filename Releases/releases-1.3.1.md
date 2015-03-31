---
layout: download
menuitem: Releases
title: Version 1.3.1 Dammastock.
order: 2
---

# Rekall Memory Forensic Releases

## Version 1.3.1 Dammastock.

This release was made at the Rekall Memory Forensic Workshop at DFRWS. For the
first time, we ran this workshop completely from the interactive Rekall web
console. It was an astounding success, and an impressive medium to deliver an
interactive workshop (Check it out
[here](http://memory-analysis.rekall-forensic.com) ).

### Release Highlights

Memory Acquisition
: The major thrust for this release was the updating of the Pmem Acquisition tools
  to [AFF4](http://www.aff4.org). In addition to the stable WinPmem 1.6.2, we have
  made available an experimental pre-release of the WinPmem 2.0 series.

The new imagers feature:

1. A consistent interface. The same command line arguments used for all operating systems.
2. The new memory image format we have standardized on is AFF4. This allows us
   to store multiple streams in the image, such as the page file and additional
   files.
3. The pmem imagers are able to embed different files inside the final AFF4
   image, such as the kernel image and miscellaneous binaries.

Note that the new imagers are still considered pre-release. Please test but
continue using the old imagers for critical work.


GUI Web Console
: The GUI was expanded to accommodate multiple sessions. A Rekall session is an
  object encapsulating all we know about a specific image. With multiple session
  support in the GUI, we are able to write a single web console document which
  runs plugins on multiple images simultaneously.

* The GUI was also adapted to allow for the export of static versions of the
  document, which can be hosted on a simple web server.

Windows
: Rekall will now automatically fetch missing profiles from the Microsoft Symbol
  Server for critical modules.

* This was a huge pain point in the past - when MS updated kernels through a
  patch the kernel was rebuilt resulting in a new profile. By the time the
  Rekall team pushed the new profile to the profile repository, Rekall was
  non-functional, requiring users to know how to generate new profiles manually.

* This new release adds a setting (you can set it in the configuration file
  permanently or just use the flag `--autodetect_build_local`). The following
  values are allowed:

  * `none` means that Rekall will not fetch profiles from the symbol server (but
    will still use the profile repositories specified in `repository_path`).

  * `basic` is the default setting. Rekall will fetch profiles for selected
    modules, such as the kernel, win32k.sys, ntdll, tcpip etc. This is usually
    good enough for most plugins to function correctly.

  * `full` in this setting Rekall will try the symbol server for all profiles it
    does not know about. This can be very slow but will produce the best
    outcome (e.g. disassembly output will be fully annotated).

Linux
: Added support for XEN paravirtualized guests.