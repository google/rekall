================================
Rekall Memory Forensic Framework
================================

The Rekall Framework is a completely open collection of tools, implemented in
Python under the GNU General Public License, for the extraction of digital
artifacts from volatile memory (RAM) samples.  The extraction techniques are
performed completely independent of the system being investigated but offer
visibilty into the runtime state of the system. The framework is intended to
introduce people to the techniques and complexities associated with extracting
digital artifacts from volatile memory samples and provide a platform for
further work into this exciting area of research.

The Rekall distribution, as well as further information is available
from: http://www.rekall-forensic.com/

Quick start
-----------

Rekall is available as a python package installable via the pip package
manager. Simply type (for example on Linux):

- sudo pip install rekall

To have all the dependencies installed. You still need to have python and pip
installed first.

To be able to run the ipython notebook, the following are also required:

- pip install Jinja2 MarkupSafe Pygments astroid pyzmq tornado wsgiref

If you want to use the yarascan plugin, install [yara and yara-python](http://plusvic.github.io/yara/).

For windows, Rekall is also available as a self contained installer
package. Please check the download page for the most appropriate installer to
use [Rekall-Forensic.com](http://www.rekall-forensic.com/)

Mailing Lists
-------------

Mailing lists to support the users and developers of Rekall
can be found at the following address:

    rekall-discuss@googlegroups.com

Licensing and Copyright
-----------------------

Copyright (C) 2007-2011 Volatile Systems
Copyright 2012-2014 Google Inc. All Rights Reserved.

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

Bugs and Support
----------------

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

Further documentation is available at
http://www.rekall-forensic.com/
