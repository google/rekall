from rekall import testlib

from rekall.plugins.renderers import visual_aides


class MemoryMapTest(testlib.RekallBaseUnitTestCase):
    def testRuns(self):
        runs = [
            dict(start=101, end=500, value="Foo"),
            dict(start=0, end=100, value="Bar"),
            dict(start=0, end=10, value="Foo"),
            dict(start=401, end=500, value="Baz"),
            dict(start=501, end=502, value="Bork")]
        legend = visual_aides.MapLegend(legend=[
            ("F", "Foo", (0xff, 0x00, 0x00)),
            ("B", "Bar", (0x00, 0xff, 0x00)),
            ("Bz", "Baz", (0x00, 0x00, 0xff)),
            ("Bk", "Bork", (0xff, 0xff, 0xff))
        ])

        rbmap = visual_aides.RunBasedMap(
            runs=runs, legend=legend, resolution=10, column_count=5)

        cells = list(rbmap.cells)

        self.assertEqual(len(rbmap.rows), 11)
        self.assertEqual(len(cells), 51)

        # Should be blended 1:1
        self.assertEqual(cells[0]["bg"], (127.5, 127.5, 0))

        # Shouldn't blend.
        self.assertEqual(cells[-1]["bg"], (0xff, 0xff, 0xff))
