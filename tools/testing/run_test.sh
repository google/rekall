#!/bin/bash

# This is the main test runner. We sync the git repositories and then run the
# tap script which will test over all tests.

HOME=/home/rekalltest/
PYTHON_EGG_CACHE=$HOME

source $HOME/Test/bin/activate

# Sync the latest rekall repository
cd $HOME/rekall/
git fetch --all
git reset --hard origin/master

# Install all the components separately in the right order.
cd rekall-core/
python setup.py install
cd ../rekall-gui/
python setup.py install
cd ../
python setup.py install

# Sync to the latest test harness.
cd $HOME/rekall-test/
git fetch --all
git reset --hard origin/master

echo Running test from $PWD

# Run the tap process and wait for results.
python $HOME/rekall/tools/testing/tap.py -c $HOME/tap.yaml
if [ $? -ne 0 ]; then
   echo "error with $1" >&2
else
   echo "Tests pass."
fi
