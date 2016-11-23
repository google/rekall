import subprocess

from rekall import testlib as rekall_testlib
from rekall_agent import testlib
from rekall_agent.client_actions import osquery

def check_if_osquery_installed():
    """Only enable this test if osqueryi is installed."""
    try:
        subprocess.check_call(["osqueryi", "--version"])
        return True
    except (IOError, OSError):
        return False


@rekall_testlib.disable_if(check_if_osquery_installed)
class TestOSQuery(testlib.ClientAcionTest):

    def testOSQuery(self):
        action = osquery.OSQueryAction(session=self.session)
        action.query = "select * from mounts"
        action.location = self.get_test_location("test")

        action.run()

        data = self.dump_test_collection("test")
        self.assertTrue(len(data) > 0)
        for row in data:
            self.assertTrue(row["blocks"] >= 0)


if __name__ == "__main__":
    testlib.main()
