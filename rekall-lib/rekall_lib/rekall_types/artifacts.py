from rekall_lib import serializer

class SourceType(serializer.SerializedObject):
    schema = [
        dict(name="type",
             doc="The source type"),
        dict(name="attributes", type="dict",
             doc="Attributes of the source type"),
        dict(name="supported_os", repeated=True,
             doc="Supported OS list"),
    ]


class Artifact(serializer.SerializedObject):
    schema = [
        dict(name="name",
             doc="The artifact name (Must be unique)."),
        dict(name="doc",
             doc="The description of the artifact."),
        dict(name="sources", type=SourceType, repeated=True,
             doc="A list of sources to fetch this artifact.")
    ]
