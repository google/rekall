from rekall import testlib

from rekall.entities import entity


class EntityTest(testlib.RekallBaseUnitTestCase):
    def testFromAsDict(self):
        data = {"Process/pid": 1,
                "Process/command": "init"}

        x = entity.Entity.fromdict(data)
        self.assertEqual(x.asdict(), data)
