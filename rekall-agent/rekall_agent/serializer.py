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
import collections
import json
import yaml

import arrow

from rekall import registry
from rekall import utils


class FieldDescriptor(object):
    """A descriptor for a field."""

    def __init__(self, descriptor):
        self.descriptor = descriptor

    def validate(self, value, session=None):
        _ = session
        return value

    def to_primitive(self, value):
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
        return long(value)

    def get_default(self, session=None):
        return self.descriptor.get("default", 0)


class BoolDescriptor(FieldDescriptor):
    def validate(self, value, session=None):
        _ = session
        if isinstance(value, bool):
            return value
        return bool(value)

    def get_default(self, session=None):
        return False


class FloatDescriptor(FieldDescriptor):
    def validate(self, value, session=None):
        _ = session
        return float(value)

    def get_default(self, session=None):
        return 0


class EpochDescriptor(FieldDescriptor):
    def validate(self, value, session=None):
        if isinstance(value, (float, int)):
            value = arrow.Arrow.fromtimestamp(value)

        elif not isinstance(value, arrow.Arrow):
            raise ValueError("Value must be timestamp or arrow.Arrow instance.")

        return value

    def to_primitive(self, value):
        return value.float_timestamp

    def from_primitive(self, value, session=None):
        _ = session
        return self.validate(value)


class DictDescriptor(FieldDescriptor):
    def validate(self, value, session=None):
        _ = session
        if not isinstance(value, dict):
            raise ValueError("Value must be unicode string")

        return value

    def get_default(self, session=None):
        return {}

class UnicodeDescriptor(FieldDescriptor):
    def validate(self, value, session=None):
        _ = session
        if not isinstance(value, basestring):
            raise ValueError("Value must be unicode string")

        return unicode(value)

    def get_default(self, session=None):
        return unicode(self.descriptor.get("default", ""))


class StringDescriptor(FieldDescriptor):
    def validate(self, value, session=None):
        _ = session
        if not isinstance(value, basestring):
            raise ValueError("Value must be string")

        return str(value)

    def to_primitive(self, value):
        return value.encode("base64")

    def from_primitive(self, value, session=None):
        return value.decode("base64")

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

        return unicode(value)


class NestedDescriptor(FieldDescriptor):
    """A nested field type."""

    # The SerializedObject class for the nested object.
    nested = None

    def validate(self, value, session=None):
        nested_cls = SerializedObject.ImplementationByClass(self.nested)

        # Direct assignment of the correct type.
        if value.__class__ is nested_cls:
            return value

        # Assign a dict to this object, parse from primitive.
        elif isinstance(value, (dict, basestring, int, long, float)):
            return nested_cls.from_primitive(value, session=session)

        # A subclass is assigned.
        elif issubclass(value.__class__, nested_cls):
            return value

        raise ValueError("value is not valid.")

    def to_primitive(self, value):
        result = value.to_primitive()

        # If we are actually containing a subclass of the nested class then make
        # sure to mark the data with the full class name so it can be properly
        # unserialized.
        if value.__class__.__name__ != self.nested:
            result["__type__"] = value.__class__.__name__

        return result

    def from_primitive(self, value, session=None):
        if isinstance(value, SerializedObject):
            return value

        if isinstance(value, dict):
            # Support instantiating a derived class from the raw data.
            value_cls_name = value.get("__type__", self.nested)
            value_cls = SerializedObject.ImplementationByClass(value_cls_name)
            if value_cls is None:
                raise TypeError(
                    "Unknown implementation for %s" % value_cls_name)

            nested_cls = SerializedObject.ImplementationByClass(self.nested)
            if not issubclass(value_cls, nested_cls):
                raise TypeError(
                    "Object %s can not be initialized from type %s" %
                    (self.nested, value_cls_name))

            value = value.copy()
            value.pop("__type__", None)
            return value_cls.from_primitive(value, session=session)

        nested_cls = SerializedObject.ImplementationByClass(self.nested)
        return nested_cls.from_primitive(value, session=session)

    def get_default(self, session=None):
        return SerializedObject.ImplementationByClass(self.nested)(
            session=session)


class RepeatedHelper(list):
    def __init__(self, descriptor, initializer=None, session=None):
        super(RepeatedHelper, self).__init__(initializer or [])
        self.descriptor = descriptor
        self._hooks = []
        self._session = session
        if not session:
            raise RuntimeError("Session must be provided.")

    def add_update_cb(self, cb):
        self._hooks.append(cb)

    def to_primitive(self):
        result = []
        for x in self:
            result.append(x.to_primitive())

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
        field_type = descriptor.get("type", unicode)
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

    def to_primitive(self, value):
        return [self.descriptor_obj.to_primitive(x) for x in value]

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


# This dispatches the class implementing as declared type.
DISPATCHER = dict(
    int=IntDescriptor,
    unicode=UnicodeDescriptor,
    str=StringDescriptor,
    bytes=StringDescriptor,
    choices=ChoicesDescriptor,
    epoch=EpochDescriptor,
    dict=DictDescriptor,
    bool=BoolDescriptor,
    float=FloatDescriptor,
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


class SerializedObject(object):
    """An object with a fixed schema which can be easily serialized."""

    __metaclass__ = SerializedObjectCompiler

    # This contains the object's schema.
    schema = [

    ]

    def __init__(self, session=None):
        if session is None:
            raise RuntimeError("Session must be provided.")

        self._data = {}
        self._session = session
        self._hooks = []
        self._unknowns = {}

    @classmethod
    def from_keywords(cls, session=None, **kwargs):
        if session is None:
            raise ValueError("Session must be provided.")

        try:
            tmp = session._unstrict_serialization
            session._unstrict_serialization = True

            result = cls(session=session)
            for k, v in kwargs.iteritems():
                result.SetMember(k, v)
        finally:
            session._unstrict_serialization = tmp
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
        return [x.descriptor for x in cls._descriptors.itervalues()]

    def HasMember(self, name):
        return name in self._data

    def GetMember(self, name, get_default=True):
        result = self._data.get(name)
        if result is None and get_default:
            default = self._descriptors[name].get_default(
                session=self._session)
            if isinstance(default, (SerializedObject, RepeatedHelper)):
                default.add_update_cb(
                    lambda n=name, d=default: self.SetMember(n, d))

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

        for k, v in kwargs.iteritems():
            self.SetMember(k, v)

    def merge(self, other):
        """Merge the other object into this one."""
        for k, v in other.iteritems():
            if isinstance(v, SerializedObject):
                self.GetMember(k).merge(v)
            else:
                self.SetMember(k, v)

        return self

    def to_primitive(self, with_type=True):
        """Convert ourselves to a dict."""
        result = self._unknowns.copy()
        for k, v in self.iteritems():
            result[k] = self._descriptors[k].to_primitive(v)

        if with_type:
            result["__type__"] = self.__class__.__name__

        return result

    def to_json(self):
        return json.dumps(self.to_primitive(), sort_keys=True)

    @classmethod
    def from_json(cls, json_string, session=None):
        data = json.loads(json_string or "{}")
        return cls.from_primitive(data, session=session)

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
        data_cls = cls.ImplementationByClass(cls_type)
        if not issubclass(data_cls, cls):
            raise ValueError("Incompatible class types: %s != %s" % (
                cls_type, cls.__name__))

        result = data_cls(session=session)

        for k, v in data.iteritems():
            descriptor = data_cls._descriptors.get(k)
            if descriptor is None:
                # We do not know about this field, we preserve it but do not set
                # it.
                result.set_unknown(k, v)
            else:
                result.SetMember(k, descriptor.from_primitive(
                    v, session=session))

        return result

    def __nonzero__(self):
        return bool(self._data)

    def __eq__(self, other):
        if self.__class__ is not other.__class__:
            return False

        return self._data == other._data

    def __unicode__(self):
        return unicode(self.to_primitive())

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
        for key, item in data.iteritems():
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
            except TypeError, exc:
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
        for k, v in fields.items():
            result[k] = v

        return result


def load_from_dict(data, names=None):
    """Loads definitions from a yaml file.

    Returns a dict mapping class names to class implementations.
    """
    # If not specified define all the classes.
    if names is None:
        names = data.keys()

    result = {}
    for name in names:
        schema = data[name]
        result[name] = type(name, (SerializedObject, ), dict(schema=schema))

    return result
