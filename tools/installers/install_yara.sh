#!/bin/bash

export VIRTUALENV=$(pwd)/py27
export BUILD=$(pwd)/yara-build
export PATH=$BUILD/autotools-bin/bin:$PATH

rm -rf $BUILD

mkdir -p $BUILD
cd $BUILD

# Build autoconf

curl -OL http://ftp.gnu.org/gnu/autoconf/autoconf-2.68.tar.xz
tar -xzf autoconf-2.68.tar.xz
cd autoconf-2.68
./configure --prefix=$BUILD/autotools-bin && make && make install

cd $BUILD

# Build automake

curl -OL http://ftp.gnu.org/gnu/automake/automake-1.11.tar.gz
tar -xzf automake-1.11.tar.gz
cd automake-1.11
./configure --prefix=$BUILD/autotools-bin && make && make install

cd $BUILD

# Build libtool

curl -OL http://ftpmirror.gnu.org/libtool/libtool-2.4.2.tar.gz
tar -xzf libtool-2.4.2.tar.gz
cd libtool-2.4.2
./configure --prefix=$BUILD/autotools-bin && make && make install

cd $BUILD

# Build dumbass YARA

curl -OL https://github.com/plusvic/yara/archive/v3.4.0.tar.gz
tar -xzf v3.4.0.tar.gz
cd yara-3.4.0

libtoolize  # LOL, because it's 1997, apparently.

# Yes this needs to run twice. The first time fails, but creates files (mostly
# from libtool) that allow the second run to succeed. Sigh.
autoreconf --force --install
autoreconf --force --install

./configure --prefix=$BUILD/autotools-bin && make && make install
