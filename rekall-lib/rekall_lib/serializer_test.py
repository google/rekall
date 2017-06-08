from rekall import testlib
from rekall_agent import serializer


class TestObject1(serializer.SerializedObject):
    schema = [
        dict(name="C1", type="int"),
        dict(name="R1", type="unicode", repeated=True),
        dict(name="C2", type="str"),
    ]


# Note that forward declarations are not currently implemented so declaration
# order matters.
class TestObject2(serializer.SerializedObject):
    schema = [
        # Nested field.
        dict(name="N1", type="TestObject1"),
    ]


class ExtendedTestObject1(TestObject1):
    """An inherited object.

    This will inherit all the fields from TestObject1 automatically.
    """

    schema = [
        dict(name="extra")
    ]


class TestSerializer(testlib.RekallBaseUnitTestCase):
    """Test the serializer framework."""

    def testFieldValidation(self):
        test_obj = TestObject1(session=self.session)
        # Should not be allowed to set a string.
        with self.assertRaises(ValueError):
            test_obj.C1 = "Hello"

        test_obj.C1 = 10
        self.assertEqual(test_obj.C1, 10)

        # Setting a float will convert to an int.
        test_obj.C1 = 20.5
        self.assertEqual(test_obj.C1, 20)

    def testNestedFields(self):
        test_obj = TestObject2(session=self.session)
        test_obj.N1.C1 = 10

        self.assertEqual(test_obj.N1.C1, 10)
        self.check_serialization(
            test_obj, {'N1': {'C1': 10L, '__type__': 'TestObject1'}})

    def testUnknownFields(self):
        """Test handling of unknown fields.

        When parsing from JSON it should be ok to include unknown fields, since
        they could represent a new version of the object. Any unknown fields
        should be stored though and later emitted upon serialization.
        """
        json_blob = """
        {"C1": 5, "U1": "foobar"}
        """
        # This should parse properly.
        obj = TestObject1.from_json(json_blob, session=self.session)

        self.assertEqual(obj._unknowns["U1"], "foobar")

        #  Make sure there is no such attribute.
        with self.assertRaises(AttributeError):
            _ = obj.U1

        # Ensure unknowns get re-serialized.
        self.assertEqual(obj.to_primitive(),
                         dict(C1=5, U1="foobar", __type__="TestObject1"))

    def check_serialization(self, test_obj, primitive):
        self.assertEqual(test_obj.to_primitive(with_type=False), primitive)

        self.assertEqual(
            test_obj.__class__.from_primitive(
                primitive, session=self.session),
            test_obj)

        self.assertEqual(test_obj.__class__.from_primitive(
            primitive, session=self.session).to_primitive(with_type=False),
                         primitive)


    def testRepeatedField(self):
        test_obj = TestObject1(session=self.session)

        with self.assertRaises(ValueError):
            test_obj.R1.append(10)

        test_obj.R1.append("hello")
        test_obj.R1.append("world")

        self.check_serialization(test_obj, {'R1': [u'hello', u'world']})

    def testStringSerialization(self):
        """Makes sure that serializing a string field base64 encodes it."""
        test_obj = TestObject1(session=self.session)
        test_obj.C2 = "hello"

        with self.assertRaises(ValueError):
            test_obj.C2 = 10

        TestObject1.from_primitive({'C2': 'aGVsbG8=\n'}, session=self.session)

        self.check_serialization(test_obj, {'C2': 'aGVsbG8=\n'})

    def testInheritance(self):
        """We support a natural form of object inheritance.

        This means that we can derive a data type and assign to a field of the
        type of the base class with a derived data type. Upon de-serialization
        the derived class will be instantiated. This is achieved by including an
        explicit __type__ field in the raw JSON output.

        In this test we define container.N1 to be of type TestObject1. We extend
        TestObject1 with a new type (ExtendedTestObject1). We are allowed to
        assign to N1 this extended type, and when we serialize it the system
        will note the proper name of the class in the __type__ attribute.

        De-serialization will use the __type__ attribute to automatically
        restore the correct type in the N1 field.
        """
        # A derived object inherits all the base object's fields.
        test_obj = ExtendedTestObject1.from_keywords(extra="foo", C1=5,
                                                     session=self.session)

        container = TestObject2(session=self.session)

        # Can not assign an int to this field - it is still strongly typed.
        with self.assertRaises(ValueError):
            container.N1 = 10

        # container.N1 is defined to be of type TestObject1 which is a base
        # class of ExtendedTestObject1.
        container.N1 = test_obj

        self.assertTrue(test_obj, ExtendedTestObject1)
        self.assertTrue(type(container.N1), ExtendedTestObject1)

        # Now convert to primitive type.
        primitive_data = container.to_primitive()

        # There will be a __type__ field which declares the proper nested type.
        self.assertEqual(primitive_data["N1"]["__type__"],
                         "ExtendedTestObject1")

        json_data = container.to_json()

        # When decoding we receive the correct type in this field.
        decoded = TestObject2.from_json(json_data, session=self.session)

        self.assertTrue(type(decoded.N1), ExtendedTestObject1)


if __name__ == "__main__":
    testlib.main()
