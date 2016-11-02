# -*- coding: utf-8 -*-
"""Test the cloud locations for contacting Google Cloud Storage."""
import argparse
import StringIO
import time

from rekall import testlib
from rekall_agent.locations import cloud

# Note that this test requires a valid connection to the cloud.
parser = argparse.ArgumentParser(description='Rekall Agent Cloud test')
parser.add_argument('--config', nargs="?", help='configuration file.')
parser.add_argument('--verbose', action="store_true")


class TestGCS(testlib.RekallBaseUnitTestCase):
    """Test the GCS based Location objects."""

    def setUp(self):
        super(TestGCS, self).setUp()
        with self.session:
            if args.verbose:
                self.session.SetParameter("logging_level", 10)

            self.session.SetParameter("agent_configuration", args.config)
        self.config = self.session.GetParameter("agent_config_obj")

        # Unique string to write to the bucket.
        self.string = str(time.time())
        self.filename = "%s.txt" % time.time()

    def tearDown(self):
        # Remove the filename from the bucket.
        try:
            self.config.server.service_account.create_oauth_location(
                self.filename).delete()
        except IOError:
            pass

    def test_gcs_location(self):
        """Tests common methods on all GCSLocation."""
        location_obj = (self.config.server
                        .service_account.create_oauth_location(
                            path=self.filename))
        canonical = location_obj.get_canonical()
        self.assertEqual(type(canonical), cloud.GCSLocation)
        self.assertEqual(canonical.bucket, self.config.server.bucket)
        self.assertEqual(canonical.path, self.filename)

    def test_oauth_token_location(self):
        """Test the GCSOAuth2BasedLocation.

        Most of the controller code uses this kind of location. The
        GCSOAuth2BasedLocation has all privileges on the bucket and
        can do anything. Of course you need the service_account
        credentials to mint such a token.
        """
        now = int(time.time())

        location_obj = (self.config.server
                        .service_account.create_oauth_location(
                            path="path/" + self.filename))

        # Reading and writing.
        location_obj.write_file("Hello world")
        self.assertEqual(location_obj.read_file(), "Hello world")
        stat = location_obj.stat()

        self.assertTrue(stat.size > 0)
        self.assertEqual(stat.location.path, "path/" + self.filename)
        self.assertTrue(stat.created.timestamp >= now)
        self.assertTrue(stat.created.timestamp <= int(time.time()))

        # Now test the list_files() method.
        directory_obj = (self.config.server
                         .service_account.create_oauth_location(
                             path="path/"))
        files = list(directory_obj.list_files())
        paths = [x.location.path for x in files]

        # We should see the new file in there.
        self.assertTrue("path/" + self.filename in paths)

        # Deletion.
        location_obj.delete()

        # Note that reading a non existent file returns the empty
        # string.
        self.assertEqual(location_obj.read_file(), "")

        # We can tell its not there by stat() call returning None.
        self.assertEqual(location_obj.stat(), None)

    def test_signed_url(self):
        """Test that we can read from a signed URL."""
        # First write some unique string.
        location_obj = (self.config.server
                        .service_account.create_signed_url_location(
                            path=self.filename, mode="w"))

        # We can not read from this location.
        with self.assertRaises(IOError):
            location_obj.read_file()

        # We can use the location object alone to write the file.
        self.assertEqual(location_obj.write_file(self.string), True)

        # We can still not read from this location with the signed URL
        # for writing.
        with self.assertRaises(IOError):
            location_obj.read_file()

        # We need a new signed URL for reading to actually read it.
        location_obj = (self.config.server
                        .service_account.create_signed_url_location(
                            path=self.filename, mode="r"))

        # We can not write to this location using this signed URL.
        with self.assertRaises(IOError):
            location_obj.write_file("")

        # But we can read it.
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
        location_obj = (self.config.server.service_account
                        .create_signed_url_location(
                            path=self.filename, mode="w"))

        infd = self._make_file()
        location_obj.upload_local_file(fd=infd)

        location_obj = (self.config.server.service_account
                        .create_signed_url_location(
                            path=self.filename, mode="r"))

        # Now read the data again to make sure it uploaded ok.
        self.assertTrue(location_obj.read_file() == infd.getvalue())

    def test_signed_url_upload_file_resumable(self):
        """Test the resumable upload mechanism."""
        # First write some unique string.
        location_obj = (self.config.server.service_account
                        .create_signed_url_location(
                            path=self.filename, mode="w",
                            upload="resumable"))

        infd = self._make_file()
        location_obj.upload_local_file(fd=infd)

        location_obj = (self.config.server.service_account
                        .create_signed_url_location(
                            path=self.filename, mode="r"))

        # Now read the data again to make sure it uploaded ok.
        self.assertTrue(location_obj.read_file() == infd.getvalue())

    def test_policy_document(self):
        """Policy documents allow writing under a fixed path.


        Note that policy documents only allow writing. The
        GCSSignedPolicyLocation contains the fixed path prefix and a
        client controlled path_template.
        """
        obj = (self.config.server
               .service_account.create_signed_policy_location(
                   path_prefix="signed_policy/",
                   path_template="{subpath}"))

        self.assertTrue(obj.write_file(
            "Hello world", subpath=self.filename))

        # Now read the document and make sure it wrote it properly.
        location_obj = (self.config.server.service_account
                        .create_oauth_location(
                            path="signed_policy/%s" % self.filename))

        self.assertEqual(location_obj.read_file(), "Hello world")

        # Clean up.
        location_obj.delete()

    def test_policy_document_unicode_filename(self):
        """Check that we can upload unicode filenames."""
        self.filename = u"倍可亲/美国中文网.txt"

        obj = (self.config.server
               .service_account.create_signed_policy_location(
                   path_prefix="signed_policy/",
                   path_template="{subpath}"))

        self.assertTrue(obj.write_file(
            "Hello world", subpath=self.filename))

        # Now read the document and make sure it wrote it properly.
        location_obj = (self.config.server.service_account
                        .create_oauth_location(
                            path=u"signed_policy/%s" % self.filename))

        self.assertEqual(location_obj.read_file(), "Hello world")

        # Clean up.
        location_obj.delete()

    def test_read_modify_write_file(self):
        def modify(filename):
            with open(filename, "wb") as fd:
                fd.write("hello world")

        a = cloud.GCSOAuth2BasedLocation(session=self.session)
        a.bucket = "rekall-temp"
        a.path = "test.txt"
        a.read_modify_write_local_file(modify)


if __name__ == "__main__":
    args, unknown_args = parser.parse_known_args()
    if not args.config:
        print """
This test requires a valid GCS configuration.

You can make one with the agent_server_initialize_gcs plugin.
"""

    else:
        testlib.main(argv=["test"] + unknown_args)
