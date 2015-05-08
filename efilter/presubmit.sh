#!/bin/bash

# Find the top-level dir and change to it:

# Change working dir to one containing this script.
cd "$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Recurse up until we get to the top-level.
while [ ! -e "setup.py" ]
do
  cd ..

  if [[ "$(pwd)" == "/" ]]
  then
    echo "Cannot find top level directory."
    exit -1
  fi
done

echo "Working directory is $(pwd)"

git diff master --name-only -- efilter | grep -F '.py' | xargs -I{} autopep8 --ignore E309,E711 -i -r {}

# Run the unit test suite.
python -m unittest discover efilter

git diff master --name-only -- efilter | grep -F '.py' | xargs -I{} pylint --rcfile tools/devel/pylintrc {}
