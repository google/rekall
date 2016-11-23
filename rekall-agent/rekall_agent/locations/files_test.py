import os
import StringIO

from rekall import testlib
from rekall_agent.config import agent
from rekall_agent.locations import files
from rekall_agent.policies import files as policy_files


class TestFileLocation(testlib.RekallBaseUnitTestCase):
    """Test the file based Location object."""

    string1 = "String 1"

    def setUp(self):
        self.session = self.MakeUserSession()
        # Create a new agent state.
        self.config = agent.Configuration.from_keywords(
            session=self.session,
            server=policy_files.FileBasedServerPolicy.from_keywords(
                session=self.session,
                root_path=self.temp_directory)
        )

        self.session.SetCache("agent_config_obj", self.config)

    def test_read_file(self):
        self.test_path = os.path.join(self.temp_directory, "test.txt")

        # Write the file normally.
        with open(self.test_path, "wb") as fd:
            fd.write(self.string1)

        # The location is defined in terms of the base of the installation.
        location_obj = files.FileLocation.from_keywords(
            session=self.session,
            path_prefix=self.temp_directory,
            path_template="{basename}.txt")

        # Ensure that the path is properly expanded.
        self.assertEqual(location_obj.to_path(basename="test"),
                         self.test_path)

        # Check that template expansion works.
        self.assertEqual(
            self.string1, location_obj.read_file(basename="test"))

    def test_write_file(self):
        self.test_path = os.path.join(self.temp_directory, "test2.txt")

        # The location is defined in terms of the base of the installation.
        location_obj = files.FileLocation.from_keywords(
            session=self.session,
            path_prefix=self.temp_directory,
            path_template="{base}.txt")

        location_obj.write_file(self.string1, base="test2")

        self.assertEqual(open(self.test_path, "rb").read(), self.string1)

    def test_upload_local_file(self):
        self.test_path = os.path.join(self.temp_directory, "test.txt")

        # Write the file normally.
        with open(self.test_path, "wb") as fd:
            fd.write(self.string1)

        # The location is defined in terms of the base of the installation.
        location_obj = files.FileLocation.from_keywords(
            session=self.session,
            path_prefix=self.temp_directory,
            path_template="{base}.txt")

        location_obj.upload_local_file(self.test_path, base="test")

        # Make sure that the new location contains the correct data.
        self.assertEqual(location_obj.read_file(base="test"), self.string1)

    def test_upload_file_object(self):
        # The location is defined in terms of the base of the installation.
        location_obj = files.FileLocation.from_keywords(
            session=self.session,
            path_prefix=self.temp_directory,
            path_template="{base}.txt")

        location_obj.upload_file_object(
            StringIO.StringIO(self.string1), base="test")

        # Make sure that the new location contains the correct data.
        self.assertEqual(location_obj.read_file(base="test"), self.string1)


if __name__ == "__main__":
    testlib.main()
