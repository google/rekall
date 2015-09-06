#!/bin/bash

REKALL_ENV="${BUILD_DIR}/rekall_env"
VIRTUALENV="py27"

# Cleanup!

rm -rf build/ dist/

# Sanity checks:

# Ensure we're running on Darwin:
if [ $(uname -s) != "Darwin" ]
then
  echo "Cross-building OS X Rekall is not supported."
  echo "Please run this on an OS X machine running 10.7 or later."
  exit 1
else
  echo "OS is Darwin."
fi

type gcc && type virtualenv

if [ $? -ne 0 ]
then
  echo "You must have installed Xcode and virtualenv."
  exit 2
fi

# Looks like we're all set.

echo "Building rekall distribution for Darwin..."

# Find the top-level Rekall dir and change to it:

# Change working dir to one containing this script.
cd "$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Recurse up until we get to the top-level.
while [ ! -e "setup.py" ]
do
  cd ..
done

# Initializiation

echo "Working directory is $(pwd)"

# Create a virtualenv for us.

if [ ! -e "${VIRTUALENV}" ]
then
   echo "Creating virtualenv in $(pwd)/${VIRTUALENV}"
   virtualenv $VIRTUALENV
fi

source "${VIRTUALENV}/bin/activate"

# Yara is weird and we have a whole separate script to build it.
if [ ! -e "yara-build" ]
then
  ./tools/installers/install_yara.sh
  if [ $? -ne 0 ]
  then
      echo "Yara didn't install properly. Try installing it from source."
      exit 3
  fi
fi

cd yara-build/yara-3.4.0/yara-python/
python setup.py build
python setup.py install
cd -

# Apple built Python with flags that are not supported by the compiler they
# ship with the OS *facepalm*. This tells clang to stop short of exploding once
# it throws its tantrum.

cd rekall-core/
ARCHFLAGS=-Wno-error=unused-command-line-argument-hard-error-in-future python setup.py install
if [ $? -ne 0 ]
then
  echo "Build failed. I got nothing."
  exit 4
fi
cd -

cd rekall-gui/
ARCHFLAGS=-Wno-error=unused-command-line-argument-hard-error-in-future python setup.py install
if [ $? -ne 0 ]
then
  echo "Build failed. I got nothing."
  exit 4
fi
cd -

# Everything should be built now. Lets pull pyinstaller and try to build dist.
python tools/installers/fix_deps.py
pip install pyinstaller

# This is needed to get readline to work properly.
easy_install -a readline
rm -rf dist/ build/
pyi-build -y tools/installers/darwin.spec

if [ $? -ne 0 ]
then
  echo "Pyinstaller failed. Sorry about that - you still have the virtualenv!"
  exit 5
fi

# Copy over manuskript because I couldn't figure out a simple way to get
# pyinstaller to do it.
cp -r rekall-core/resources/* dist/rekal/
cp -r rekall-gui/manuskript dist/rekal/manuskript
cp -r rekall-gui/rekall_gui/plugins/webconsole dist/rekal/webconsole

echo "All done!"
echo "Virtualenv with rekall in $(pwd)/${VIRTUALENV}"
echo "Standalone distribution in $(pwd)/dist"
