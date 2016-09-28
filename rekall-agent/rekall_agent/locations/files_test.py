import os

from rekall import testlib
from rekall_agent.config import agent
from rekall_agent.locations import files


class TestFileLocation(testlib.RekallBaseUnitTestCase):
    """Test the file based Location object."""

    string1 = "String 1"

    def setUp(self):
        self.session = self.MakeUserSession()
        # Create a new agent state.
        agent_state = agent.ClientConfiguration(session=self.session)

        # The base of the agent state is inside the temp directory.
        agent_state.base_location = files.FileLocation.from_keywords(
            session=self.session, path=self.temp_directory)

        self.session.SetCache("AgentState", agent_state)


    def test_read_file(self):
        self.test_path = os.path.join(self.temp_directory, "test.txt")

        # Write the file normally.
        with open(self.test_path, "wb") as fd:
            fd.write(self.string1)

        # The location is defined in terms of the base of the installation.
        location_obj = files.FileLocation.from_keywords(
            session=self.session,
            path="{base_location}/test.txt")

        # Ensure that the path is properly expanded.
        self.assertEqual(location_obj.full_path, self.test_path)
        self.assertEqual(self.string1, location_obj.read_file())

    def test_write_file(self):
        self.test_path = os.path.join(self.temp_directory, "test2.txt")

        # The location is defined in terms of the base of the installation.
        location_obj = files.FileLocation.from_keywords(
            session=self.session,
            path="{base_location}/test2.txt")

        location_obj.write_file(self.string1)

        self.assertEqual(open(self.test_path, "rb").read(), self.string1)

    def test_upload_local_file(self):
        self.test_path = os.path.join(self.temp_directory, "test.txt")

        # Write the file normally.
        with open(self.test_path, "wb") as fd:
            fd.write(self.string1)

        # The location is defined in terms of the base of the installation.
        location_obj = files.FileLocation.from_keywords(
            session=self.session,
            path="{base_location}/test2.txt")

        self.status = None
        def completion(status):
            self.status = status

        location_obj.upload_local_file(self.test_path, completion)

        # Ensure that the completion routine is called with success.
        self.assertEqual(self.status.code, 200)

        # Make sure that the new location contains the correct data.
        self.assertEqual(location_obj.read_file(), self.string1)


if __name__ == "__main__":
    testlib.main()
