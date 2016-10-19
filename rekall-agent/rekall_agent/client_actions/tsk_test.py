from rekall import resources
from rekall_agent import testlib
from rekall_agent.client_actions import files
from rekall_agent.client_actions import tsk


class TestTSK(testlib.ClientAcionTest):
    def setUp(self):
        super(TestTSK, self).setUp()

        # Add a fake mount point to the image.
        mount_tree_hook = files.MountPointHook(session=self.session)
        mount_tree = {}
        mount_tree_hook._add_to_tree(
            mount_tree, "/mnt/",
            resources.get_resource("winexec_img.dd",
                                   package="rekall_agent",
                                   prefix="test_data"),
            "ext2")

        self.session.SetParameter("mount_points", mount_tree)

    def testTSK(self):
        action = tsk.TSKListDirectoryAction(session=self.session)
        action.path = "/mnt/a"
        action.vfs_location = self.get_test_location("test")
        self.assert_baseline("testTSK", list(action.collect()))

    def testTSKRecursive(self):
        action = tsk.TSKListDirectoryAction(session=self.session)
        action.path = "/mnt/a"
        action.recursive = True
        action.depth = 1
        action.vfs_location = self.get_test_location("test")
        self.assert_baseline("testTSKRecursive", list(action.collect()))


if __name__ == "__main__":
    testlib.main()
