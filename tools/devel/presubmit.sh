#!/bin/bash

# Find the top-level Rekall dir and change to it:

# Change working dir to one containing this script.
cd "$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Recurse up until we get to the top-level.
while [ ! -e "setup.py" ]
do
  cd ..
  
  if [[ "$(pwd)" == "/" ]]
  then
    echo "Cannot find rekall directory."
    exit -1
  fi
done

echo "Working directory is $(pwd)"

for f in $( git diff master --name-only -- . | grep ".py"); do
  if [ -e $f ]; then
    autopep8 --ignore E309,E711 -i -r --max-line-length 80 $f
    pylint --rcfile tools/devel/pylintrc $f
  fi
done

# Run the unit test suite.
./tools/testing/test_suite.py -c ../test/unit/tests.config
