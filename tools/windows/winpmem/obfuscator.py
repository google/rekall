import random

class Interpolator(object):

    def __init__(self):
        self.key = [random.randint(1, 255) for _ in range(50)]

    def __getitem__(self, item):
        if item == "key":
            return "".join(["\\x%02X" % x for x in self.key])

        # Add a NULL terminator
        item += "\x00"

        # Xor with the key.
        return "".join(["\\x%02X" % (ord(y) ^ x)
                        for x, y in zip(self.key, item)])


def interpolate_file(filename):
    data = open(filename + ".in", "rb").read()

    with open(filename, "wb") as fd:
        fd.write(data % Interpolator())

interpolate_file("api.h")
