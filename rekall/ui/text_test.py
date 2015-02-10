from rekall import testlib

from rekall.ui import text


class CellTest(testlib.RekallBaseUnitTestCase):

    def testNesting(self):
        c1 = text.Cell(value="Hello, world!", width=6, align="r")
        self.assertEqual(c1.lines, ["Hello,", "world!"])
        c1.rewrap(width=7)
        self.assertEqual(c1.lines, [" Hello,", " world!"])
        c1.rewrap(align="l")
        self.assertEqual(c1.lines, ["Hello, ", "world! "])

        c2 = text.Cell(value="I am a line of text.", width=13, align="l")
        self.assertEqual(c2.lines, ["I am a line  ", "of text.     "])
        c2.rewrap(width=8)
        self.assertEqual(c2.lines, ["I am a  ", "line of ", "text.   "])
        self.assertEqual(c2.width, 8)
        self.assertEqual(c2.height, 3)

        c3 = text.JoinedCell(c1, c2, tablesep="|")
        self.assertEqual(c3.lines, ["Hello, |I am a  ",
                                    "world! |line of ",
                                    "       |text.   "])
        self.assertEqual(c3.height, 3)
        self.assertEqual(c3.width, 7 + 1 + 8)

        c4 = text.JoinedCell(c3, c1)
        self.assertEqual(len(c4.cells), 3)
        self.assertEqual(c4.width, 7 + 1 + 8 + 1 + 7)

    def testColors(self):
        # Invisible characters shouldn't affect reported width.
        c1 = text.Cell(value="Hello, world!", highlights=[(0, 6, "RED", None)])
        self.assertEqual(c1.width, 13)

    def testPreserveNewLines(self):
        c1 = text.Cell(value="Hello,\n world!")
        self.assertEqual(c1.lines[0], "Hello, ")
