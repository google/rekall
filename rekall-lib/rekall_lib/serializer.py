"""A Serialization system based on json.

There are some popular choices for serialization formats in python varying
between a flexible, undefined schema and rigid, predefined schema. For example
one can use Pickle to serialize (almost) arbitrary objects, which is one end of
the scale. The opposite end of the scale is the use protocol buffers which must
be declared in advance, compiled and then parsed at runtime.

Protocol buffers offer some advantage over json encoding. The main advantage is
the rigid validated data schema for encoded messages - This guarantees
consistent encoding/decoding of data to/from the wire format on multiple
systems/languages and programs.

Protocol buffers also offer other advantages but in the Rekall context these are
less relevant. For example, protobuf encoded messages are smaller but not by
much (especially if one uses gzip compression). Theoretically protocol buffers
should parse faster than json but this is not the case in Python (since the
Python protobuf library is pretty slow and json parsing is done in C).

Protobufs also claim to be supported by different languages, but in reality json
is more widely supported out of the box by most languages (avoiding the need to
have extra complications like protocol buffer compilers and worrying about the
compiler and runtime library being in sync).

So when weighing up the choices of serialization formats we settled on JSON
because:

1) It is faster to parse/serialize in Python. In Rekall (unlike GRR) We do not
   actually manipulate too many serialized objects, so speed is not too
   important anyway.

2) Size of the serialized messages is not too much more and Rekall does not
   store too many serialized objects, nor do we store large messages. So this
   consideration is not important for us.

3) Does not need protobuf compilers - json parses out of the box in most
   languages.

4) JSON can also be parsed without knowing in advance the JSON message
   format. This makes it a better export format than protocol buffers which must
   have their .proto files shared across different users.

Nevertheless using raw JSON has the major disadvantage that it is
schema-less. We therefore implement a strongly typed schema on top of JSON
serialization in this module.

This module implements some extra features over the protobuf library which make
it more useful:

1. Type checking on assignment (assigned type must be an instance of the field
   type or the assignment will fail). This helps to catch bugs where incorrect
   fields are assigned.

2. Assignment semantics are more pythonic - a reference is kept in the parent
   object instead of making a copy each time.

3. Messages are normal classes which means it is encouraged to attach methods to
   them. This is very useful since deserializing a json message suddenly brings
   into existence an entire hierarchy of objects with methods and attributes
   with no additional work. It is common in the code to attach methods to
   certain types of messages and then call them directly in an OO way.

4. The OO model supports class hierarchy in the usual way. This means you can
   define a message field to be of a type and then extend that type to provide
   other implementations. This works exactly as expected:

This is a baseclass message:

class Location(SerializedObject):
  schema = [
    ....
  ]

A nested message contains a field of the baseclass type

class SomeMessage(SerializedObject):
  schema = [
    dict(name="field1", type=Location)
  ]

Now if we extend Location:

class ExtraLocation(Location):
   schema = [
     ....
   ]

It is possible to assign the derived class to the message:

message = SomeMessage()
message.field1 = ExtraLocation()

# And the serialized json stream retains the derived type information.
serialized_string = message.to_json()

So when we recreate the message it will do the right thing:

new_message = SomeMessage.from_json(serialized_string)

Now:
type(new_message.field1) == ExtraLocation


"""
from builtins import str
from past.builtins import basestring
from builtins import object
import collections
import json
import yaml

import arrow
import base64

from rekall_lib import registry
from rekall_lib import utils
from future.utils import with_metaclass
import six

if six.PY3:
    unicode = str



def StripImpl(name):
    if name.endswith("Impl"):
        return name[:-4]
    return name


class Session(object):
    """A session keeps serialization state."""
    _unstrict_serialization = False


class FieldDescriptor(object):
    """A descriptor for a field."""

    def __init__(self, descriptor):
        self.descriptor = descriptor

    def validate(self, value, session=None):
        _ = session
        return value

    def to_primitive(self, value, with_type=True):
        return value

    def from_primitive(self, value, session=None):
        _ = session
        return value

    def get_default(self, session=None):
        _ = session
        return self.descriptor.get("default")


class IntDescriptor(FieldDescriptor):
    def validate(self, value, session=None):
        _ = session
        return int(value)

    def get_default(self, session=None):
        return self.descriptor.get("default", 0)


class BoolDescriptor(FieldDescriptor):
    def validate(self, value, session=None):
        _ = session
        if isinstance(value, bool):
            return value
        return bool(value)

    def get_default(self, session=None):
        return self.descriptor.get("default", False)


class FloatDescriptor(FieldDescriptor):
    def validate(self, value, session=None):
        _ = session
        return float(value)

    def get_default(self, session=None):
        return self.descriptor.get("default", 0.0)


class EpochDescriptor(FieldDescriptor):
    def validate(self, value, session=None):
        if isinstance(value, (float, int)):
            value = arrow.Arrow.fromtimestamp(value)

        elif not isinstance(value, arrow.Arrow):
            raise ValueError("Value must be timestamp or arrow.Arrow instance.")

        return value

    def to_primitive(self, value, with_type=True):
        return value.float_timestamp

    def from_primitive(self, value, session=None):
        _ = session
        return self.validate(value)


class DictDescriptor(FieldDescriptor):
    def validate(self, value, session=None):
        _ = session
        if not isinstance(value, dict):
            raise ValueError("Value must be a dict")

        return value

    def get_default(self, session=None):
        return {}

class UnicodeDescriptor(FieldDescriptor):
    def validate(self, value, session=None):
        _ = session
        if not isinstance(value, basestring):
            raise ValueError("Value must be unicode string")

        return str(value)

    def get_default(self, session=None):
        return str(self.descriptor.get("default", ""))


class StringDescriptor(FieldDescriptor):
    """Stores raw bytes."""

    def validate(self, value, session=None):
        _ = session
        if not isinstance(value, basestring):
            raise ValueError("Value must be string")

        return utils.SmartStr(value)

    def to_primitive(self, value, with_type=True):
        return utils.SmartUnicode(base64.b64encode(value))

    def from_primitive(self, value, session=None):
        return base64.b64decode(utils.SmartStr(value))

    def get_default(self, session=None):
        return str(self.descriptor.get("default", ""))


class ChoicesDescriptor(FieldDescriptor):

    def validate(self, value, session=None):
        _ = session
        choices = self.descriptor["choices"]
        if callable(choices):
            choices = choices()

        if value not in choices:
            raise ValueError("Value must be one of %s" % choices)

        return str(value)


class NestedDescriptor(FieldDescriptor):
    """A nested field type."""

    # The SerializedObject class for the nested object.
    nested = None

    def validate(self, value, session=None):
        # Check that the assigned value is a subclass of the nested class.
        nested_cls = SerializedObject.ImplementationByClass(self.nested)

        # Direct assignment of the correct type.
        if value.__class__ is nested_cls:
            return value

        # Assign a dict to this object, parse from primitive.
        elif isinstance(value, (dict, basestring, int, int, float)):
            return nested_cls.from_primitive(value, session=session)

        # A subclass is assigned.
        elif issubclass(value.__class__, nested_cls):
            return value

        raise ValueError("value is not valid.")

    def to_primitive(self, value, with_type=True):
        result = value.to_primitive(with_type=with_type)

        # If we are actually containing a subclass of the nested class then make
        # sure to mark the data with the full class name so it can be properly
        # unserialized.
        if value.__class__.__name__ != self.nested:
            result["__type__"] = StripImpl(value.__class__.__name__)

        return result

    def from_primitive(self, value, session=None):
        if isinstance(value, SerializedObject):
            return value

        if isinstance(value, dict):
            # Support instantiating a derived class from the raw data.
            value_cls_name = value.get("__type__", self.nested)

            # Allow specialized implementations for serializable types.
            value_cls = SerializedObject.get_implemetation(value_cls_name)
            if value_cls is None:
                raise TypeError(
                    "Unknown implementation for %s" % value_cls_name)

            # Validate that the value is an instance of the nested class.
            nested_cls = SerializedObject.ImplementationByClass(self.nested)
            if not issubclass(value_cls, nested_cls):
                raise TypeError(
                    "Object %s can not be initialized from type %s" %
                    (self.nested, value_cls_name))

            value = value.copy()
            value.pop("__type__", None)
            return value_cls.from_primitive(value, session=session)

        nested_cls = SerializedObject.get_implemetation(self.nested)
        return nested_cls.from_primitive(value, session=session)

    def get_default(self, session=None):
        return SerializedObject.get_implemetation(self.nested)(
            session=session)


class RepeatedHelper(list):
    def __init__(self, descriptor, initializer=None, session=None):
        super(RepeatedHelper, self).__init__(initializer or [])
        self.descriptor = descriptor
        self._hooks = []
        if not session:
            session = Session()
        self._session = session

    def add_update_cb(self, cb):
        self._hooks.append(cb)

    def to_primitive(self, with_type=True):
        result = []
        for x in self:
            result.append(x.to_primitive(with_type=with_type))

        return result

    def _signal_modified(self):
        """Signal all interested parties that this object is modified."""
        if self._hooks:
            for hook in self._hooks:
                hook()
            self._hook = []

    def append(self, item):
        item = self.descriptor.validate(item, session=self._session)
        super(RepeatedHelper, self).append(item)
        self._signal_modified()

    def extend(self, items):
        items = [self.descriptor.validate(x, session=self._session)
                 for x in items]
        super(RepeatedHelper, self).extend(items)
        self._signal_modified()


class RepeatedDescriptor(FieldDescriptor):
    """Described repeated fields."""

    def __init__(self, descriptor):
        super(RepeatedDescriptor, self).__init__(descriptor)
        field_type = descriptor.get("type", "unicode")
        field_name = descriptor["name"]

        # If the type is a class then check the name in the dispatcher.
        if isinstance(field_type, type):
            field_type = DISPATCHER.get(field_type.__name__)

        else:
            field_type = DISPATCHER.get(field_type)


        if field_type is None:
            raise TypeError("Unknown type for field %s" % field_name)

        self.descriptor_obj = field_type(self.descriptor)

    def validate(self, value, session=None):
        return RepeatedHelper(
            self.descriptor_obj,
            [self.descriptor_obj.validate(x, session=session)
             for x in value],
            session=session)

    def to_primitive(self, value, with_type=True):
        return [self.descriptor_obj.to_primitive(
            x, with_type=with_type) for x in value]

    def from_primitive(self, value, session=None):
        if not isinstance(value, (list, tuple)):
            raise TypeError(
                "Nested Field %s can only be initialized from lists" %
                (self.descriptor["name"]))

        return RepeatedHelper(
            self.descriptor_obj,
            [self.descriptor_obj.from_primitive(x, session=session)
             for x in value],
            session=session)

    def get_default(self, session=None):
        if "default" in self.descriptor:
            return self.descriptor["default"][:]

        return RepeatedHelper(self.descriptor_obj, session=session)


# This dispatches the class implementing as declared type. The
# dispatcher maps the declared field type to the descriptor which
# handles it.
DISPATCHER = dict(
    int=IntDescriptor,
    choices=ChoicesDescriptor,
    epoch=EpochDescriptor,
    dict=DictDescriptor,
    bool=BoolDescriptor,
    float=FloatDescriptor,
    unicode=UnicodeDescriptor,
    str=StringDescriptor,
    bytes=StringDescriptor,
)


class SerializedObjectCompiler(registry.MetaclassRegistry):
    """Compile the SerializedObject class after it is defined.

    The user specifies the schema when they declare the class. We then create
    field descriptors for all declared fields and automatically insert accessors
    for all fields.
    """

    def __new__(mcs, cls_name, parents, dct):
        """We parse the schema and create accessors for fields."""
        # Parse the schema and add properties for all fields.
        descriptors = collections.OrderedDict()
        for parent in parents:
            descriptors.update(getattr(parent, "_descriptors", {}))

        for field in dct.get("schema", []):
            field_name = field["name"]
            field_type = field.get("type", "unicode")
            repeated = field.get("repeated")

            if isinstance(field_type, basestring):
                field_type = DISPATCHER.get(field_type)

            elif issubclass(field_type, SerializedObject):
                field_type = DISPATCHER.get(field_type.__name__)

            if field_type is None:
                raise TypeError("Unknown field %s" % field)

            if not issubclass(field_type, FieldDescriptor):
                raise TypeError("Unsupported field type %s" % field)

            if repeated:
                descriptors[field_name] = RepeatedDescriptor(field)
            else:
                descriptors[field_name] = field_type(field)

            getter = lambda self, n=field_name: self.GetMember(n)
            setter = lambda self, v, n=field_name: self.SetMember(n, v)
            dct[field_name] = utils.safe_property(
                getter, setter, None, field_name)

        # The descriptors for all the fields.
        dct["_descriptors"] = descriptors

        # Add a new descriptor type for fields that declare this type.
        DISPATCHER[cls_name] = type("%sDescriptor" % cls_name,
                                    (NestedDescriptor, ),
                                    dict(nested=cls_name))

        return super(SerializedObjectCompiler, mcs).__new__(
            mcs, cls_name, parents, dct)


class SerializedObject(with_metaclass(SerializedObjectCompiler, object)):
    """An object with a fixed schema which can be easily serialized."""

    # This contains the object's schema.
    schema = [

    ]

    def __init__(self, session=None):
        if session is None:
            session = Session()

        self._data = {}
        self._session = session
        self._hooks = []
        self._unknowns = {}

    @classmethod
    def get_implemetation(cls, name):
        """Gets a class implementing the name specified.

        In order to implement the Pimpl pattern we allow implementations to
        define classes implementing an simple serializable type.

        For example, if a serializable type is:
          class Foo(SerializedObject):...

        Then we may implement this object in another file like:

           class FooImpl(Foo): ...

        Unserializing will then choose the implementation over the base type
        when creating it from the Raw JSON. For example, the following JSON
        object will actually contain an instance if FooImpl:

          {"__type__": "Foo"}

        We need PIMPL in order to separate the definition of the
        SerializedObject which may need to be used in code which is not capable
        of running any of the methods offered by the baseclasses (but may still
        need to create and serialize such objects).

        The receiver of the serialized JSON object will then instantiate the
        object with concrete implementations.

        For example: in common code between client and server:
          class Foo(SerializedObject):
            schema = [
             ...
            ]

            def some_method(self):
              raise NotImplementedError()

        Clients can import this code and not have to have concrete
        implementations for the methods. In Client code:

        x = Foo.from_keywords(foo=1, bar2=2)

        send x.to_primitive() ->
        {"__type__": "Foo", "foo": 1, "bar": 2}

        Then the server will define the actual implementation:

        class FooImpl(Foo):
          def some_method(self):
            ..... <- real implementation

        and can then simply parse it and receive the implementation:
        x = serializer.unserialize(json_dict)
        x.some_method()   <-- Run the FooImpl.some_method()

        For now we keep it really simple: An implementation class name must have
        the suffix "Impl" which implements the base SerializedObject and must
        also inherit from it.
        """
        # Fallback to the base type if not available.
        base_cls = cls.ImplementationByClass(name)

        # Match an implementation if that is available.
        result = cls.ImplementationByClass(name + "Impl")
        if result is not None:
            if not issubclass(result, base_cls):
                raise AttributeError(
                    "Class Implementation %s must inherit from %s" % (
                        result, name))

            return result
        else:
            return base_cls

    @classmethod
    def from_keywords(cls, session=None, **kwargs):
        if session is None:
            session = Session()

        result = cls(session=session)
        for k, v in kwargs.items():
            result.SetMember(k, v)

        return result

    def copy(self):
        """Make a copy of this message."""
        return self.__class__.from_primitive(
            session=self._session, data=self.to_primitive())

    def add_update_cb(self, cb):
        self._hooks.append(cb)

    def _signal_modified(self):
        """Signal all interested parties that this object is modified."""
        if self._hooks:
            for hook in self._hooks:
                hook()
            self._hook = []

    @classmethod
    def get_descriptors(cls):
        return [x.descriptor for x in cls._descriptors.values()]

    def HasMember(self, name):
        return name in self._data

    def GetMultiName(self, names):
        item = self
        for name in names:
            item = item.GetMember(name)

            if item is None:
                break

        return item

    def GetMember(self, name, get_default=True):
        if "." in name:
            return self.GetMultiName(name.split("."))

        result = self._data.get(name)
        if result is None and get_default:
            default = self._descriptors[name].get_default(
                session=self._session)
            if isinstance(default, (SerializedObject, RepeatedHelper)):
                default.add_update_cb(
                    lambda n=name, d=default: self.SetMember(n, d))
            elif isinstance(default, dict):
                self.SetMember(name, default)

            return default

        return result

    def SetMember(self, name, value):
        self._signal_modified()

        # Setting to None deletes the field.
        if value is None:
            self._data.pop(name, None)
            return

        try:
            value = self._descriptors[name].validate(
                value, session=self._session)
        except ValueError as e:
            # When decoding old data, we do not want to raise an error if the
            # field is invalid. This can happen if the field definition has
            # since changed In that case we would rather set the field to None
            # than to have invalid data in that field.

            # When used normally, this code should raise because it is called
            # during member assignments.
            if not self._session._unstrict_serialization:
                raise ValueError("While validating %s.%s: %s" % (
                    self.__class__.__name__, name, e))
        except KeyError:
            raise ValueError("Unable to set member %s in %s: No such field." %
                             (name, self.__class__.__name__))


            value = None
        self._data[name] = value

    def set_unknown(self, k, v):
        self._unknowns[k] = v

    def iteritems(self):
        for key in self._descriptors:
            value = self.GetMember(key, get_default=False)
            if value is not None:
                yield key, value

    def update(self, _other=None, **kwargs):
        if _other:
            kwargs.update(_other)

        for k, v in kwargs.items():
            self.SetMember(k, v)

    def merge(self, other):
        """Merge the other object into this one."""
        for k, v in other.items():
            if isinstance(v, SerializedObject):
                self.GetMember(k).merge(v)
            else:
                self.SetMember(k, v)

        return self

    def to_primitive(self, with_type=True):
        """Convert ourselves to a dict."""
        result = self._unknowns.copy()
        for k, v in self.iteritems():
            result[k] = self._descriptors[k].to_primitive(
                v, with_type=with_type)

        if with_type:
            result["__type__"] = StripImpl(self.__class__.__name__)

        return result

    def to_json(self):
        return json.dumps(self.to_primitive(), sort_keys=True)

    @classmethod
    def from_json(cls, json_string, session=None, strict_parsing=False):
        data = json.loads(utils.SmartUnicode(json_string) or "{}")
        return unserialize(data, session=session,
                           strict_parsing=strict_parsing, type=cls)

    @classmethod
    def from_primitive(cls, data, session=None):
        """Load ourselves from a pure dict."""
        if not data:
            data = {}

        if isinstance(data, SerializedObject):
            return data

        if not isinstance(data, dict):
            raise ValueError("Must be initialized from dict")

        cls_type = data.get("__type__", cls.__name__)
        data_cls = cls.get_implemetation(cls_type)
        if data_cls is None or not issubclass(data_cls, cls):
            raise ValueError(
                "Incompatible class types: %s != %s (Should be inherited)" % (
                    cls_type, cls.__name__))

        result = data_cls(session=session)

        for k, v in data.items():
            if k == "__type__":
                continue
            descriptor = data_cls._descriptors.get(k)
            if descriptor is None:
                if session and not session._unstrict_serialization:
                    raise ValueError("Unknown field %s.%s" % (
                        data_cls.__name__, k))
                # We do not know about this field, we preserve it but do not set
                # it.
                result.set_unknown(k, v)
            else:
                result.SetMember(k, descriptor.from_primitive(
                    v, session=session))

        return result

    def __bool__(self):
        return bool(self._data)

    def __eq__(self, other):
        if self.__class__ is not other.__class__:
            return False

        return self._data == other._data

    def __unicode__(self):
        return str(self.to_primitive())

    def __repr__(self):
        return repr(self.to_primitive())

    def __setattr__(self, item, value):
        if not item.startswith("_") and item not in self._descriptors:
            raise AttributeError("Invalid field %s" % item)

        super(SerializedObject, self).__setattr__(item, value)

    def cast(self, target_cls):
        """Cast the current object into the target class.

        This method forces this object to be converted to the target class. This
        means that all data fields on this object will be assigned to the target
        class if it supports these fields. Fields which are not supported by the
        target class will be ignored.
        """
        return target_cls.from_primitive(
            self.to_primitive(False), session=self._session)


class OrderedYamlDict(yaml.YAMLObject, collections.OrderedDict):
    """A class which produces an ordered dict."""
    yaml_tag = "tag:yaml.org,2002:map"

    @classmethod
    def to_yaml(cls, dumper, data):
        value = []
        node = yaml.nodes.MappingNode(cls.yaml_tag, value)
        for key, item in data.items():
            node_key = dumper.represent_data(key)
            node_value = dumper.represent_data(item)
            value.append((node_key, node_value))

        return node

    @classmethod
    def construct_mapping(cls, loader, node, deep=False):
        """Based on yaml.loader.BaseConstructor.construct_mapping."""
        if not isinstance(node, yaml.MappingNode):
            raise yaml.loader.ConstructorError(
                None, None, "expected a mapping node, but found %s" % node.id,
                node.start_mark)

        mapping = OrderedYamlDict()
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            try:
                hash(key)
            except TypeError as exc:
                raise yaml.loader.ConstructorError(
                    "while constructing a mapping", node.start_mark,
                    "found unacceptable key (%s)" % exc, key_node.start_mark)

            value = loader.construct_object(value_node, deep=deep)
            mapping[key] = value

        return mapping

    @classmethod
    def from_yaml(cls, loader, node):
        """Parse the yaml file into an OrderedDict so we can preserve order."""
        fields = cls.construct_mapping(loader, node, deep=True)
        result = cls()
        for k, v in list(fields.items()):
            result[k] = v

        return result


def load_from_dicts(data, names=None):
    """Loads definitions from a yaml file.

    Returns a dict mapping class names to class implementations.
    """
    # If not specified define all the classes.
    if names is None:
        names = list(data.keys())

    result = {}
    for name in names:
        schema = data[name]
        result[name] = type(name, (SerializedObject, ), dict(schema=schema))

    return result


def unserialize(data, session=None, strict_parsing=True, type=None):
    """Unserialize a dict into a SerializedObject.

    Args:
      strict_parsing: If enabled we silently drop invalid field assignments
      instead of raise exceptions. This is useful when the system likely to
      generate the data has changed its definitions.
    """
    if isinstance(data, basestring):
        data = json.loads(data)

    impl = type
    if impl is None:
        if not isinstance(data, dict) or "__type__" not in data:
            raise ValueError(
                "Unserialize is only possible from typed serialized dict.")

        type_name = data["__type__"]
        impl = SerializedObject.get_implemetation(type_name)
        if impl is None:
            raise ValueError(
                "No implementation for serialized type %s" % data["__type__"])

    if session is None:
        session = Session()

    if strict_parsing:
        return impl.from_primitive(data, session=session)

    session._unstrict_serialization = True
    try:
        return impl.from_primitive(data, session=session)
    finally:
        session._unstrict_serialization = False


def robust_unserialize(data, default=None):
    try:
        return unserialize(data)
    except ValueError:
        return default
