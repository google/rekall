import mock
from rekall import testlib
from rekall.plugins.response import common


class TestFileSpecs(testlib.RekallBaseUnitTestCase):

    def testFileSpecUnix(self):
        test_obj = common.FileSpec("/usr/bin/ls")
        self.assertEqual(test_obj.basename, "ls")
        self.assertEqual(unicode(test_obj.dirname), "/usr/bin")
        self.assertEqual(test_obj.components(), ["usr", "bin", "ls"])
        self.assertEqual(test_obj.os_path(), "/usr/bin/ls")

        # It does not matter if the path has a / at the end or not. It
        # still refers to the same object.
        test_obj = common.FileSpec("/usr/bin/")
        self.assertEqual(test_obj.basename, "bin")
        self.assertEqual(unicode(test_obj.dirname), "/usr")

        test_obj = common.FileSpec("/")
        self.assertEqual(test_obj.basename, "")
        self.assertEqual(unicode(test_obj.dirname), "/")
        self.assertEqual(test_obj.components(), [])

    @mock.patch("os.path.sep", "\\")
    def testFileSpecWindows(self):
        """Test windows paths."""
        test_obj = common.FileSpec("c:\\Windows\System32\\notepad.exe", path_sep="\\")
        self.assertEqual(test_obj.basename, "notepad.exe")
        self.assertEqual(unicode(test_obj.dirname), "c:\\Windows\\System32")
        self.assertEqual(test_obj.components(), ["c:", "Windows", "System32",
                                                 "notepad.exe"])

        self.assertEqual(test_obj.os_path(), "c:\\Windows\System32\\notepad.exe")


class TestFileInformation(testlib.RekallBaseUnitTestCase):
    def testUnixFiles(self):
        pass


if __name__ == "__main__":
    testlib.main()
