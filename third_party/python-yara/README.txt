Python Yara
===========

This is an improved binary installer for the standard yara-python package as
available from the yara project:

https://github.com/plusvic/yara

The main problem with the standard distribution is the difficulty in installing
and distributing since it needs to link into libyara.so. This means you need to
make sure to include this file somewhere where it can be linked and built.

The build process is also non-standard and requires a lot of manual involvement
(run visual studio in windows, configure, make, make install in linux and OSX).

This is a slightly reworked setup.py file which builds a static version of the
python module. This package will be distributed via PyPi and so can just work
simply by installing using PIP:

pip install yara-python

This builds equally well on linux, OSX and Windows platforms.

How to build
------------

If you did a git checkout you need to pull the sub modules:

git submodules init

cd third_party/python-yara/
python setup.py install
