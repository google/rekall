#!/bin/bash

REKALL_ENV="${BUILD_DIR}/rekall_env"
VIRTUALENV="py27"

# Cleanup!

rm -rf build/ dist/ $VIRTUALENV/

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

echo "Creating virtualenv in $(pwd)/${VIRTUALENV}"
virtualenv $VIRTUALENV
source "${VIRTUALENV}/bin/activate"

# Yara is weird and needs to be installed first.

pip install yara

if [ $? -ne 0 ]
then
  echo "Yara didn't install properly. Try installing it from source."
  exit 3
fi

# Apple built Python with flags that are not supported by the compiler they
# ship with the OS *facepalm*. This tells clang to stop short of exploding once
# it throws its tantrum.

ARCHFLAGS=-Wno-error=unused-command-line-argument-hard-error-in-future python setup.py install

if [ $? -ne 0 ]
then
  echo "Build failed. I got nothing."
  exit 4
fi

# Everything should be built now. Lets pull pyinstaller and try to build dist.

pip install pyinstaller
rm -rf dist/ build/
pyi-build -y tools/installers/darwin.spec

if [ $? -ne 0 ]
then
  echo "Pyinstaller failed. Sorry about that - you still have the virtualenv!"
  exit 5
fi

# Copy over manuskript because I couldn't figure out how to get pyinstaller to
# do that simply.

cp -r manuskript dist/rekal/manuskript
cp -r rekall/plugins/tools/webconsole dist/rekal/webconsole

echo "All done!"
echo "Virtualenv with rekall in $(pwd)/${VIRTUALENV}"
echo "Standalone distribution in $(pwd)/dist"

