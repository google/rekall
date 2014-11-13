#!/bin/bash

python -m unittest rekall.entities.query.efilter_test rekall.entities.query.validator_test rekall.entities.query.analyzer_test rekall.entities.query.matcher_test rekall.obj_test

autopep8 --ignore E309,E711 -i -r rekall/entities/ rekall/plugins/common/entities.py rekall/plugins/collectors/ rekall/plugins/renderers/entities.py

pylint --rcfile tools/devel/pylintrc rekall/entities/ rekall/plugins/common/entities.py rekall/plugins/collectors rekall/plugins/renderers/entities.py
