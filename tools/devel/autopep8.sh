#!/bin/bash

# Only run autopep8 on the current directory
autopep8 --ignore E309,E711 -i -r --max-line-length 80 $@
