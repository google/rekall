import os
import mock

from rekall import testlib
from rekall import utils
from rekall.plugins.response import common
from rekall.plugins.response import files


class TestGlob(testlib.RekallBaseUnitTestCase):
    """Test file operations."""

    def testGlobComponents(self):
        """Check to ensure the components are created properly."""
        glob_plugin = files.IRGlob(session=self.session)
        path_components = glob_plugin.convert_glob_into_path_components(
            "/usr/*/ls")
        self.assertListEqual([str(x) for x in path_components],
                             ["LiteralComponent:usr",
                              "RegexComponent:.*\Z(?ms)",
                              "LiteralComponent:ls"])

        glob_plugin = files.IRGlob(session=self.session, path_sep="\\")
        path_components = glob_plugin.convert_glob_into_path_components(
            "c:\\windows\\**\*.exe")
        self.assertListEqual([str(x) for x in path_components],
                             ["LiteralComponent:c:",
                              "LiteralComponent:windows",
                              "RecursiveComponent:.*\Z(?ms)",
                              "RegexComponent:.*\\.exe\\Z(?ms)"])

    def testComponents(self):
        self.component_cache = utils.FastStore(50)
        literal = files.LiteralComponent(session=self.session,
                                         cache=self.component_cache,
                                         component="passwd")

        path_spec = common.FileSpec("/etc")
        result = list(literal.filter(path_spec))
        self.assertTrue("/etc/passwd" in [unicode(x) for x in result])

        regex = files.RegexComponent(session=self.session,
                                     cache=self.component_cache,
                                     component="pass.+")

        result = list(regex.filter(path_spec))
        self.assertTrue("/etc/passwd" in [unicode(x) for x in result])

        recursive = files.RecursiveComponent(session=self.session,
                                             cache=self.component_cache,
                                             component=".+")

        result = list(recursive.filter(path_spec))
        self.assertTrue("/etc/ssh/ssh_config" in [unicode(x) for x in result])

    def _touch(self, path):
        with open(path, "wb") as fd:
            fd.write("")

    def _make_temp_directory(self):
        self._touch(os.path.join(self.temp_directory, "boo.txt"))
        os.makedirs(os.path.join(self.temp_directory, "foo"))
        self._touch(os.path.join(self.temp_directory, "foo/boo2.txt"))

        # Drop a symlink to / - if we follow links this will crash.
        os.symlink("/", os.path.join(self.temp_directory, "link"))

    def testGlob(self):
        self._make_temp_directory()
        glob_plugin = files.IRGlob(session=self.session, globs=[
            self.temp_directory + "/*.txt"])
        result = list(glob_plugin.collect())
        self.assertTrue("boo.txt" in [os.path.basename(unicode(x["path"].filename))
                                      for x in result])
        self.assertEqual(len(result), 1)

        glob_plugin = files.IRGlob(session=self.session, globs=[
            self.temp_directory + "/**/*.txt"])
        result = list(glob_plugin.collect())
        paths = [os.path.basename(unicode(x["path"].filename))
                 for x in result]
        self.assertEqual(["boo.txt", "boo2.txt"], paths)


if __name__ == "__main__":
    testlib.main()
