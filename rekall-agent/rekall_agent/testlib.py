"""Utilities for testing Rekall Agent components."""

from rekall import testlib
from rekall_agent import action
from rekall_agent import comms


class ClientAcionTest(testlib.RekallBaseUnitTestCase):
    """Test client actions."""

    def setUp(self):
        self.session = self.MakeUserSession()
        self.data_store = comms.FileDataStore(
            base=self.temp_directory, session=self.session)

    def run_action(self, action_name, **kwargs):
        action_obj = action.AbstractAction.ImplementationByName(action_name)(
            session=self.session, comms=self.data_store, **kwargs)

        action_obj.run()

        return action_obj


def main():
    testlib.main()
