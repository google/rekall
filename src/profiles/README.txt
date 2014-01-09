Profile construction files.
===========================

Rekall contains many parsers for many different file types. Unlike other python
based file parsers, rekall does not require struct layout to be manually entered
for each file format. In many cases, the memory layout is already known to C
implementations (since the correct header files are exported.). In this case, it
is easier to extract all symbol information from debugging symbols obtained by
compiling a simple program against the required headers. We can then general
automatically a valid profile and put it in the profile repository. Note that
this is exactly the same process that Rekall uses to obtain profiles for Linux
and OSX support.

This directory contains various such programs which are used to extract domain
specific profiles for file formats. It is not normally needed for users to build
any of these programs since the final profiles are already available in the
profile repository.
