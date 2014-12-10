# pylint: disable=unused-import

from rekall import obj_test
from rekall import addrspace_test

from rekall.plugins import tests

# Please do not move these to the rekall.entities namespace as that will be
# split off and no new dependencies on Rekall should be added.
from rekall.entities import entity_test
from rekall.entities import identity_test
from rekall.entities import superposition_test

from rekall.entities.query import analyzer_test
from rekall.entities.query import efilter_test
from rekall.entities.query import matcher_test
from rekall.entities.query import validator_test

from rekall.entities.ext import indexset_test
