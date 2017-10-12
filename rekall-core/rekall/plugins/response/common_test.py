from builtins import str
import mock
from rekall import testlib
from rekall.plugins.response import common


class TestFileSpecs(testlib.RekallBaseUnitTestCase):

    def testFileSpecUnix(self):
        test_obj = common.FileSpec(u"/usr/bin/ls")
        self.assertEqual(test_obj.basename, "ls")
        self.assertEqual(utils.SmartUnicode(test_obj.dirname), u"/usr/bin")
        self.assertEqual(test_obj.components(), [u"usr", u"bin", u"ls"])
        self.assertEqual(test_obj.os_path(), u"/usr/bin/ls")

        # It does not matter if the path has a / at the end or not. It
        # still refers to the same object.
        test_obj = common.FileSpec(u"/usr/bin/")
        self.assertEqual(test_obj.basename, u"bin")
        self.assertEqual(str(test_obj.dirname), u"/usr")

        test_obj = common.FileSpec(u"/")
        self.assertEqual(test_obj.basename, u"")
        self.assertEqual(str(test_obj.dirname), u"/")

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
        test_obj = common.FileSpec(u"c:\\Windows\System32\\notepad.exe",
                                   path_sep=u"\\")
        self.assertEqual(test_obj.basename, u"notepad.exe")
        self.assertEqual(str(test_obj.dirname), u"c:\\Windows\\System32")
        self.assertEqual(test_obj.components(), [u"c:", u"Windows", u"System32",
                                                 u"notepad.exe"])

        self.assertEqual(test_obj.os_path(), u"c:\\Windows\System32\\notepad.exe")

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
