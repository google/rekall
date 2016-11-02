# -*- coding: utf-8 -*-
"""Test the cloud locations for contacting Google Cloud Storage."""
import StringIO
import shutil
import tempfile
import threading
import time

import portpicker

from rekall import session as rekall_session
from rekall import testlib
from rekall_agent import crypto
from rekall_agent.config import agent
from rekall_agent.locations import http
from rekall_agent.servers import http as http_server


class TestHTTPServer(testlib.RekallBaseUnitTestCase):
    """Test the HTTP based Location objects.

    Unlike the GCS locations, the HTTP server only has a single type
    of location which can do everything.
    """

    @classmethod
    def setUpClass(cls):
        """Bring up the HTTP server locally for tests."""
        cls._session = rekall_session.InteractiveSession(
            logging_level=10)
        port = portpicker.PickUnusedPort()
        cls.tempdir = tempfile.mkdtemp()
        cls.config = agent.Configuration.from_keywords(
            session=cls._session,
            server=http_server.HTTPServerPolicy.from_keywords(
                session=cls._session,
                base_url="http://127.0.0.1:%s/" % port,
                root_directory=cls.tempdir,
                bind_port=port,
                private_key=crypto.RSAPrivateKey(
                    session=cls._session).generate_key(),
            )
        )

        cls._session.SetParameter("agent_config_obj", cls.config)

        cls.httpd = http_server.RekallHTTPServer(
            ("127.0.0.1", port),
            http_server.RekallHTTPServerHandler,
            session=cls._session)
        cls.httpd_thread = threading.Thread(target=cls.httpd.serve_forever)
        cls.httpd_thread.daemon = True
        cls.httpd_thread.start()
        cls.base_url = "http://%s/%s" % cls.httpd.server_address

    @classmethod
    def tearDownCls(cls):
        cls.httpd.shutdown()
        shutil.rmtree(cls.tempdir)

    def setUp(self):
        super(TestHTTPServer, self).setUp()
        self.session = self._session
        with self.session:
            self.session.SetParameter("logging_level", 10)

        # Unique string to write to the bucket.
        self.string = str(time.time())
        self.filename = "%s.txt" % time.time()

    def test_http_location(self):
        location_obj = http.HTTPLocation.New(
            path_prefix=self.filename, session=self.session)

        canonical = location_obj.get_canonical()
        self.assertEqual(type(canonical), http.HTTPLocation)
        self.assertEqual(canonical.base, self.config.server.base_url)
        self.assertEqual(canonical.path_prefix, self.filename)
        self.assertEqual(canonical.path_template, "")

    def test_http_location_full_access(self):
        """The HTTPLocation is used by both the server and client.

        The server can convert a canonical HTTPLocation to a signed
        object by signing the URL with the server's private key.

        The client can not sign its own HTTPLocation object so it must
        obtain the signed URL from the server.
        """
        now = int(time.time())

        read_location_obj = http.HTTPLocation.New(
            path_prefix="/path/" + self.filename, access=["READ"],
            session=self.session)

        # Can not write with a location opened for reading only.
        with self.assertRaises(IOError):
            read_location_obj.write_file("Hello world")

        # Try again with a location for writing.
        write_location_obj = http.HTTPLocation.New(
            path_prefix="/path/" + self.filename, access=["WRITE"],
            session=self.session)

        # Reading and writing.
        write_location_obj.write_file("Hello world")

        # Can not read with a location opened for writing only.
        with self.assertRaises(IOError):
            write_location_obj.read_file()

        self.assertEqual(read_location_obj.read_file(), "Hello world")
        stat = read_location_obj.stat()

        self.assertTrue(stat.size > 0)
        self.assertEqual(stat.location.path_prefix, "/path/" + self.filename)
        self.assertEqual(stat.location.path_template, "")
        self.assertTrue(stat.created.timestamp >= now)
        self.assertTrue(stat.created.timestamp <= int(time.time()))

        # Now test the list_files() method. First try without the LIST
        # permission.
        directory_obj = http.HTTPLocation.New(
            path_prefix="/path/", access=["READ"],
            session=self.session)

        files = list(directory_obj.list_files())
        self.assertEqual(files, [])

        # In order to list the directories we need the list permission.
        directory_obj = http.HTTPLocation.New(
            path_prefix="/path/", access=["LIST"],
            session=self.session)

        files = list(directory_obj.list_files())

        paths = [x.location.path_prefix for x in files]

        # We should see the new file in there.
        self.assertTrue("/path/" + self.filename in paths)

        # Deletion.
        write_location_obj.delete()

        # Note that reading a non existent file returns the empty
        # string.
        self.assertEqual(read_location_obj.read_file(), "")

        # We can tell its not there by stat() call returning None.
        self.assertEqual(read_location_obj.stat(), None)

    def test_path_template(self):
        """Ensure that path templates are honored."""
        location_obj = http.HTTPLocation.New(
            path_prefix=self.filename, access=["READ", "WRITE"],
            session=self.session)

        # We try to extend the location with a path template. This
        # should not work because the original location object was
        # signed with no template permitted.
        location_obj.path_template = "{subdir}"
        with self.assertRaises(IOError):
            location_obj.write_file("Hello world", subdir="foo")

        # To make this work we need to provide a template and sign it.
        location_obj = http.HTTPLocation.New(
            path_prefix=self.filename, access=["READ", "WRITE"],
            path_template="{subdir}",
            session=self.session)

        location_obj.write_file("Hello world", subdir="foo")

        # Make sure it worked.
        self.assertEqual(location_obj.read_file(subdir="foo"),
                         "Hello world")

    def _make_file(self):
        # Write 10Mb.
        infd = StringIO.StringIO()
        for i in range(2 * 1024):
            tag = "%#16x" % i
            infd.write(1024 / 16 * tag)

        infd.seek(0)
        return infd

    def test_upload_file(self):
        # First write some unique string.
        location_obj = http.HTTPLocation.New(
            session=self.session, access=["WRITE", "READ"],
            path_prefix=self.filename)

        infd = self._make_file()
        location_obj.upload_local_file(fd=infd)

        # Now read the data again to make sure it uploaded ok.
        self.assertTrue(location_obj.read_file() == infd.getvalue())

    def test_unicode_filename(self):
        """Check that we can upload unicode filenames."""
        self.filename = u"倍可亲/美国中文网.txt"

        location_obj = http.HTTPLocation.New(
            session=self.session,
            path_prefix="unicode", access=["READ", "WRITE"],
            path_template="{subpath}")

        self.assertTrue(location_obj.write_file(
            "Hello world", subpath=self.filename))

        # Now read the document and make sure it wrote it properly.
        self.assertEqual(location_obj.read_file(subpath=self.filename),
                         "Hello world")

        # Clean up.
        location_obj.delete()

    def test_read_modify_write_file(self):
        def modify(filename):
            with open(filename, "wb") as fd:
                fd.write("hello world")

        location_obj = http.HTTPLocation.New(
            session=self.session, access=["WRITE", "READ"],
            path_prefix=self.filename)
        location_obj.read_modify_write_local_file(modify)

        self.assertEqual(location_obj.read_file(), "hello world")


if __name__ == "__main__":
    testlib.main()
