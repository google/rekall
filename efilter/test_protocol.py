import unittest

from efilter import dispatch
from efilter import protocol


@dispatch.polymorphic
def say_moo(cow):
    _ = cow
    raise NotImplementedError()


@dispatch.polymorphic
def graze(cow):
    _ = cow
    raise NotImplementedError()


class IBovine(protocol.Protocol):
    _protocol_functions = (say_moo, graze)


class Kyr(object):
    def say_muu(self):
        return "Muu"


IBovine.implement(for_type=Kyr,
                  implementations={
                      graze: lambda c: "Om nom nom.",
                      say_moo: lambda c: c.say_muu()})


class TypesTest(unittest.TestCase):
    def testProtocol(self):
        self.assertTrue(isinstance(Kyr(), IBovine))
        self.assertEquals(say_moo(Kyr()), "Muu")
        self.assertEqual(graze(Kyr()), "Om nom nom.")
