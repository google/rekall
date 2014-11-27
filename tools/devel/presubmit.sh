#!/bin/bash

export LINT_FILES="rekall/entities/ rekall/plugins/common/entities.py rekall/plugins/collectors/ rekall/plugins/renderers/entities.py rekall/ui/text.py rekall/plugins/renderers/base_objects.py"

export TEST_MODULES="rekall.entities.query.efilter_test rekall.entities.query.validator_test rekall.entities.query.analyzer_test rekall.entities.query.matcher_test rekall.obj_test rekall.ui.text_test"

python -m unittest $TEST_MODULES

autopep8 --ignore E309,E711 -i -r $LINT_FILES

pylint --rcfile tools/devel/pylintrc $LINT_FILES