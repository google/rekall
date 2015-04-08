#!/bin/bash

# This script simply runs in an infinite loop checking for the control
# file. When the control file appears the main test runner (run_test.sh) will be
# kicked off.

HOME=/home/rekalltest/

while true; do
  if [ -e $HOME/control ]; then
   stdbuf -oL -eL $HOME/rekall/tools/testing/run_test.sh 2>&1 > $HOME/rekall-test/runs/current.txt

   # Remove the control file until next time.
   rm -f $HOME/control

   echo "Test run done."
  fi
  sleep 5
done
