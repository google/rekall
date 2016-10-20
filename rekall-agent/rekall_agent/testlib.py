"""Utilities for testing Rekall Agent components."""
import json
import os
import sqlite3

from rekall import resources
from rekall import testlib
from rekall_agent.config import agent
from rekall_agent.locations import files


class ClientAcionTest(testlib.RekallBaseUnitTestCase):
    """Test client actions."""

    maxDiff = None

    def setUp(self):
        self.session = self.MakeUserSession()
        self.session.SetParameter(
            "agent_config_obj",
            agent.Configuration(session=self.session))

    def encode_baseline(self, data):
        return self._normalize_json(json.dumps(data, sort_keys=True, indent=2))

    def _normalize_json(self, data):
        data = "\n".join([x.rstrip() for x in data.splitlines()])
        return data

    def assert_baseline(self, name, data):
        try:
            baseline_data = self.encode_baseline(data)
            with open(os.path.join(resources.get_resource(
                    name, package="rekall_agent",
                    prefix="test_data/baselines"))) as fd:
                self.assertMultiLineEqual(self._normalize_json(fd.read()),
                                          self._normalize_json(baseline_data))
        except Exception:
            print "Unable to verify baseline %s: \n%s" % (name, baseline_data)
            raise

    def get_test_location(self, name):
        return files.FileLocation.from_keywords(
            session=self.session,
            path=os.path.join(self.temp_directory, name))

    def dump_test_collection(self, name, table="default"):
        path = os.path.join(self.temp_directory, name)
        conn = sqlite3.connect(path)
        cursor = conn.cursor()
        cursor.row_factory = sqlite3.Row

        return list(cursor.execute("select * from tbl_%s" % table))



def main():
    testlib.main()
