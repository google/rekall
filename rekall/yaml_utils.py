import yaml
import collections


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
        for k, v in fields.items():
            result[k] = v

        return result


def decode(data):
    return yaml.safe_load(data) or OrderedYamlDict()

def encode(raw_data):
    return yaml.safe_dump(raw_data, default_flow_style=False)
