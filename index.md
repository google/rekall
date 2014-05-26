---
layout: default
menuitem: Home
order: 1
---

# Rekall Memory Forensic Framework

The Rekall Framework is a completely open collection of tools, implemented in
Python under the GNU General Public License, for the extraction of digital
artifacts from volatile memory (RAM) samples.  The extraction techniques are
performed completely independent of the system being investigated but offer
visibilty into the runtime state of the system. The framework is intended to
introduce people to the techniques and complexities associated with extracting
digital artifacts from volatile memory samples and provide a platform for
further work into this exciting area of research.

The Rekall distribution is available from:
[http://www.rekall-forensic.com/](http://www.rekall-forensic.com/)

Rekall should run on any platform that supports [Python](http://www.python.org)

Rekall supports investigations of the following x86 bit memory images:

* Microsoft Windows XP Service Pack 2 and 3
* Microsoft Windows 7 Service Pack 0 and 1
* Microsoft Windows 8 and 8.1
* Linux Kernels 2.6.24 to 3.10.
* OSX 10.6-10.8.

Rekall also provides a complete memory acquisition capability for all major
operating systems (see the tools directory).

## Browse the project on github.

Rekall is hosted on [github](https://github.com/google/rekall)

## Quick start

A quick start guide is available in the [Overview](/docs/Manual/overview.html).

## Downloads

Downloads are available at the [Download Page](/downloads.html).

## Mailing Lists

Mailing lists to support users and developers of Rekall can be found at the
following addresses:

    rekall-discuss@googlegroups.com
    rekall-dev@googlegroups.com

You can subsribe to these groups via the [Google Groups
site](https://groups.google.com)

## Bugs and Support

There is no support provided with Rekall. There is NO warranty; not even for
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

If you think you've found a bug, please report it at:

    https://github.com/google/rekall/issues

In order to help us solve your issues as quickly as possible,
please include the following information when filing a bug:

* The version of rekall you're using
* The operating system used to run rekall
* The version of python used to run rekall
* The suspected operating system of the memory image
* The complete command line you used to run rekall
* Please run Rekall with the -v flag and paste output into the issue.
