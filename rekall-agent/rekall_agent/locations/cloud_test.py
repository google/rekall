import StringIO
import time

from rekall import resources
from rekall import testlib
from rekall_agent.config import server
from rekall_agent.locations import cloud


SERVICE_ACCOUNT_JSON = open(
    resources.get_resource("service_account.json",
                           package="rekall-agent",
                           prefix="test_data")
).read()


class TestGCS(testlib.RekallBaseUnitTestCase):
    """Test the GCS based Location objects."""

    def setUp(self):
        self.session = self.MakeUserSession()

        # Create a new agent state.
        self.config = server.ServerConfiguration(session=self.session)

        # The base of the agent state is a GCS bucket.
        self.config.client_config.base_location = (
            cloud.GCSLocation.from_keywords(
                session=self.session, bucket="rekall-temp"))

        self.config.service_account = cloud.ServiceAccount.from_json(
            SERVICE_ACCOUNT_JSON, session=self.session)

        # Store the configuration in the session.
        self.session.SetParameter("ServerConfig", self.config)

        # Unique string to write to the bucket.
        self.string = str(time.time())

    def test_signed_url(self):
        """Test that we can read from a signed URL."""
        # First write some unique string.
        location_obj = self.config.service_account.create_signed_url_location(
            path="hello_world.txt", mode="w")

        # We can not read from this location.
        with self.assertRaises(IOError):
            location_obj.read_file()

        # We can use the location object alone to write the file.
        self.assertEqual(location_obj.write_file(self.string), True)

        # Now try to read it.
        location_obj = self.config.service_account.create_signed_url_location(
            path="hello_world.txt", mode="r")

        # We can not write to this location.
        with self.assertRaises(IOError):
            location_obj.write_file("")

        self.assertEqual(location_obj.read_file(), self.string)

    def _make_file(self):
        # Write 10Mb.
        infd = StringIO.StringIO()
        for i in range(2 * 1024):
            tag = "%#16x" % i
            infd.write(1024 / 16 * tag)

        infd.seek(0)
        return infd

    def test_signed_url_upload_file(self):
        # First write some unique string.
        location_obj = self.config.service_account.create_signed_url_location(
            path="hello_world.txt", mode="a")

        infd = self._make_file()
        location_obj.upload_local_file(fd=infd, sync=True)

        location_obj = self.config.service_account.create_signed_url_location(
            path="hello_world.txt", mode="r")

        # Now read the data again to make sure it uploaded ok.
        self.assertTrue(location_obj.read_file() == infd.getvalue())

    def test_policy_document(self):
        # First write some unique string.
        obj = self.config.service_account.create_signed_policy_location(
            path_prefix="signed_policy/")

        self.assertTrue(obj.write_file("Hello world", subpath="foobar"))

        # Now read the document and make sure it wrote it properly.
        location_obj = self.config.service_account.create_signed_url_location(
            path="signed_policy/foobar", mode="r")

        self.assertEqual(location_obj.read_file(), "Hello world")

    def test_read_modify_write_file(self):
        def modify(filename):
            with open(filename, "wb") as fd:
                fd.write("hello world")

        a = cloud.GCSOAuth2BasedLocation(session=self.session)
        a.bucket = "rekall-temp"
        a.path = "test.txt"
        a.read_modify_write_local_file(modify)


if __name__ == "__main__":
    testlib.main()
