---
layout: download
menuitem: Releases
title: Version 1.4.0 Etzel.
order: 2
---

# Rekall Memory Forensic Releases

## Version 1.4.0 Etzel.

This is the next release of the Rekall Memory Forensic framework, codenamed
after the [Etzel pass](https://en.wikipedia.org/wiki/Etzel_Pass), not far from
Zurich.

I am excited to announce the new Rekall release is out. This release introduces
a lot of revolutionary features. The new feature list is broken as follows

* Windows support:

    * Windows 10 - This release supports WIndows 10 in most plugins. Although
      support is not complete yet, we will be working hard to make all plugins
      work.

    * Better support of pagefile. The address translation algorithm in Rekall
      has been overhauled and re-written. The new code supports describing the
      address translation process for increased provenance. On Windows, Rekall
      now supports mapping files into the physical address space. This allows
      plugins to read memory mapped files transparently (if the file data is
      available).

    * Better heap enumeration algorithms. Rekall supports enumerating more of
      the Low Fragmentation Heap (LFH).

    * All references to file names are now written with the full drive letter
      and path. Drive letters and path normalization is done by following the
      symlinks in the object tree.

    * The new mimikatz plugin contributed by Francesco Picasso has been
      completely overhauled - it now also provides master keys from lsasrv as
      well as livessp analysis.

* OSX and Linux support:

    * get common plugins like address resolver/dump/cc etc. This improves the
      workflow with these OSs.

    * Sigscan is now available for all OSs: Quickly determine if a machine
      matches a hex signature that supports wildcards.

* Framework

    * Rekall now has persistent stable cache. This means that re-launching
      Rekall on an image we analyzed in the past will suddenly be very
      fast. This is especially useful for plugins like pas2vas which take some
      time to run initially but when run subsequently this will be very fast.

    * Logging API changes. Logging is now done via the session object allowing
      external users of Rekall as a library to access log messages.

    * Efilter querying framework was externalized into its own project and
      expanded.

* Packaging

    * Rekall is now separated into three packages:

     * Rekall core contains all you need to use Rekall as a library. It does not
       have ipython as a dependency but if you also install ipython, the core
       can use it.

     * Rekall GUI is the Rekall web console GUI.

     * Rekall is now a metapackage which depends on both other packages.

* Imaging

    * Rekall gained the aff4acquire plugin in the last release but now:

    * The plugin can acquire the pagefile by itself using the Rekall NTFS parser.

    * Also acquire all the mapped files. This resolve all address translation
      requirements during the analysis stage as Rekall can later map all section
      objects to read memory mapped files.

Note: The windows binaries are also signed. Please check their signatures when
downloading.