# The Rekall Forensic and Incident Response Framework

The Rekall Framework is a completely open collection of tools,
implemented in Python under the Apache and GNU General Public License,
for the extraction and analysis of digital artifacts computer systems.

The Rekall distribution is available from:
<http://www.rekall-forensic.com/>

Rekall should run on any platform that supports
[Python](http://www.python.org)

Rekall supports investigations of the following 32bit and 64bit memory
images:

- Microsoft Windows XP Service Pack 2 and 3
- Microsoft Windows 7 Service Pack 0 and 1
- Microsoft Windows 8 and 8.1
- Microsoft Windows 10
- Linux Kernels 2.6.24 to 4.4.
- OSX 10.7-10.12.x.

Rekall also provides a complete memory sample acquisition capability for all
major operating systems (see the tools directory).

## Quick start

Rekall is available as a python package installable via the pip
package manager. To install it, first create a virtal env, switch to
it and then install rekall:

```
$ virtualenv  /tmp/MyEnv
New python executable in /tmp/MyEnv/bin/python
Installing setuptools, pip...done.
$ source /tmp/MyEnv/bin/activate
$ pip install --upgrade setuptools pip wheel
$ pip install rekall-agent
```

For windows, Rekall is also available as a self contained installer
package. Please check the download page for the most appropriate installer to
use [Rekall-Forensic.com](http://www.rekall-forensic.com/)

To install from this git repository you will need to use pip
--editable and follow the correct order of installation (otherwise pip
will pull released depedencies which might be older):

```
$ virtualenv  /tmp/MyEnv
New python executable in /tmp/MyEnv/bin/python
Installing setuptools, pip...done.
$ source /tmp/MyEnv/bin/activate
$ pip install --upgrade setuptools pip wheel
$ pip install --editable rekall/rekall-core
$ pip install --editable rekall/rekall-agent
$ pip install --editable rekall
```

On Windows you will need to install the Microsoft Visual C compilers
for python (for more info see this blog post
http://rekall-forensic.blogspot.ch/2015/09/installing-rekall-on-windows.html)

## Mailing Lists

Mailing lists to support the users and developers of Rekall
can be found at the following address:

    rekall-discuss@googlegroups.com

## Licensing and Copyright

Copyright (C) 2007-2011 Volatile Systems
Copyright 2012-2016 Google Inc. All Rights Reserved.

All Rights Reserved

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.


## Bugs and Support

There is no support provided with Rekall. There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE.

If you think you've found a bug, please report it at:

    https://github.com/google/rekall/issues

In order to help us solve your issues as quickly as possible,
please include the following information when filing a bug:

* The version of rekall you're using
* The operating system used to run rekall
* The version of python used to run rekall
* The suspected operating system of the memory image
* The complete command line you used to run rekall

## History

In December 2011, a new branch within the Volatility project was created to
explore how to make the code base more modular, improve performance, and
increase usability. The modularity allowed Volatility to be used in GRR, making
memory analysis a core part of a strategy to enable remote live forensics.  As a
result, both GRR and Volatility would be able to use each others’ strengths.

Over time this branch has become known as the "scudette" branch or the
"Technology Preview" branch.  It was always a goal to try to get these changes
into the main Volatility code base.  But, after two years of ongoing
development, the "Technology Preview" was never accepted into the Volatility
trunk version.

Since it seemed unlikely these changes would be incorporated in the future, it
made sense to develop the Technology Preview branch as a separate project. On
December 13, 2013, the former branch was forked to create a new stand-alone
project named "Rekall.” This new project incorporates changes made to streamline
the codebase so that Rekall can be used as a library. Methods for memory
acquisition and other outside contributions have also been included that were
not in the Volatility codebase.

Rekall strives to advance the state of the art in memory analysis, implementing
the best algorithms currently available and a complete memory acquisition and
analysis solution for at least Windows, OSX and Linux.


## More documentation

Further documentation is available at
http://www.rekall-forensic.com/
