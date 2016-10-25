# Rekall Memory Forensics
# Copyright 2016 Google Inc. All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

"""This module implements plugins related to forensic artifacts.

https://github.com/ForensicArtifacts
"""

__author__ = "Michael Cohen <scudette@google.com>"
import csv
import datetime
import json
import platform
import os
import StringIO
import sys
import zipfile

import yaml

from artifacts import definitions
from artifacts import errors

from rekall import plugin
from rekall import registry
from rekall import obj
from rekall import yaml_utils
from rekall.ui import text
from rekall.ui import json_renderer
from rekall.plugins.response import common


class ArtifactResult(object):
    """Bundle all the results from an artifact."""
    def __init__(self, artifact_name=None, result_type=None, fields=None):
        self.artifact_name = artifact_name
        self.result_type = result_type
        self.results = []
        self.fields = fields or []

    def __iter__(self):
        return iter(self.results)

    def add_result(self, **data):
        if data:
            self.results.append(data)

    def merge(self, other):
        self.results.extend(other)

    def as_dict(self):
        return dict(fields=self.fields,
                    results=self.results,
                    artifact_name=self.artifact_name,
                    result_type=self.result_type)



class BaseArtifactResultWriter(object):
    """Writes the results of artifacts."""
    __abstract = True

    __metaclass__ = registry.MetaclassRegistry

    def __init__(self, session=None, copy_files=False,
                 create_timeline=False):
        self.session = session
        self.copy_files = copy_files
        self.create_timeline = create_timeline

    def write_result(self, result):
        """Writes the artifact result."""

    def _create_timeline(self, artifact_result):
        """Create a new timeline result from the given result.

        We use the output format suitable for the timesketch tool:
        https://github.com/google/timesketch/wiki/UserGuideTimelineFromFile
        """
        artifact_fields = artifact_result.fields
        fields = [
            dict(name="message", type="unicode"),
            dict(name="timestamp", type="int"),
            dict(name="datetime", type="unicode"),
            dict(name="timestamp_desc", type="unicode"),
        ] + artifact_fields

        new_result = ArtifactResult(
            artifact_name=artifact_result.artifact_name,
            result_type="timeline",
            fields=fields)

        for field in artifact_fields:
            # This field is a timestamp - copy the entire row into the timeline.
            if field["type"] == "epoch":
                for row in artifact_result.results:
                    new_row = row.copy()
                    timestamp = row.get(field["name"])
                    if timestamp is None:
                        continue

                    new_row["timestamp"] = int(timestamp)
                    new_row["datetime"] = datetime.datetime.utcfromtimestamp(
                        timestamp).strftime("%Y-%m-%dT%H:%M:%S+00:00")
                    new_row["timestamp_desc"] = artifact_result.artifact_name
                    new_row["message"] = " ".join(
                        unicode(row[field["name"]]) for field in artifact_fields
                        if field["name"] in row)
                    new_result.add_result(**new_row)

        return new_result

    def __enter__(self):
        return self

    def __exit__(self, unused_type, unused_value, unused_traceback):
        return


class DirectoryBasedWriter(BaseArtifactResultWriter):
    name = "Directory"

    def __init__(self, output=None, **kwargs):
        super(DirectoryBasedWriter, self).__init__(**kwargs)
        self.dump_dir = output

        # Check if the directory already exists.
        if not os.path.isdir(self.dump_dir):
            raise plugin.PluginError("%s is not a directory" % self.dump_dir)

    def write_file(self, result):
        """Writes a FileInformation object."""
        for row in result.results:
            filename = row["filename"]
            with open(filename, "rb") as in_fd:
                with self.session.GetRenderer().open(
                        directory=self.dump_dir,
                        filename=filename, mode="wb") as out_fd:
                    while 1:
                        data = in_fd.read(1024*1024)
                        if not data:
                            break

                        out_fd.write(data)

    def _write_csv_file(self, out_fd, result):
        fieldnames = [x["name"] for x in result.fields]
        writer = csv.DictWriter(
            out_fd, dialect="excel",
            fieldnames=fieldnames)
        writer.writeheader()
        for row in result.results:
            writer.writerow(row)

    def write_result(self, result):
        """Writes the artifact result."""
        if self.copy_files and result.result_type == "file_information":
            try:
                self.write_file(result)
            except (IOError, OSError) as e:
                self.session.logging.warn(
                    "Unable to copy file %s into output: %s",
                    result["filename"], e)

        with self.session.GetRenderer().open(
                directory=self.dump_dir,
                filename="artifacts/%s.json" % result.artifact_name,
                mode="wb") as out_fd:
            out_fd.write(json.dumps(result.as_dict(), sort_keys=True))

        with self.session.GetRenderer().open(
                directory=self.dump_dir,
                filename="artifacts/%s.csv" % result.artifact_name,
                mode="wb") as out_fd:
            self._write_csv_file(out_fd, result)

        if self.create_timeline:
            with self.session.GetRenderer().open(
                    directory=self.dump_dir,
                    filename="artifacts/%s.timeline.csv" %
                    result.artifact_name,
                    mode="wb") as out_fd:
                self._write_csv_file(out_fd, self._create_timeline(result))


class ZipBasedWriter(BaseArtifactResultWriter):
    name = "Zip"

    def __init__(self, output=None, **kwargs):
        super(ZipBasedWriter, self).__init__(**kwargs)
        self.output = output

    def __enter__(self):
        self.out_fd = self.session.GetRenderer().open(
            filename=self.output, mode="wb").__enter__()

        self.outzip = zipfile.ZipFile(self.out_fd, mode="w",
                                      compression=zipfile.ZIP_DEFLATED)

        return self

    def __exit__(self, *args):
        self.outzip.close()
        self.out_fd.__exit__(*args)

    def _write_csv_file(self, out_fd, result):
        fieldnames = [x["name"] for x in result.fields]
        writer = csv.DictWriter(
            out_fd, dialect="excel",
            fieldnames=fieldnames)
        writer.writeheader()
        for row in result.results:
            writer.writerow(row)

    def write_file(self, result):
        for row in result.results:
            filename = row["filename"]
            self.outzip.write(filename)

    def write_result(self, result):
        """Writes the artifact result."""
        if self.copy_files and result.result_type == "file_information":
            try:
                self.write_file(result)
            except (IOError, OSError) as e:
                self.session.logging.warn(
                    "Unable to copy file %s into output: %s",
                    result["filename"], e)

        self.outzip.writestr("artifacts/%s.json" % result.artifact_name,
                             json.dumps(result.as_dict(), sort_keys=True),
                             zipfile.ZIP_DEFLATED)

        tmp_fd = StringIO.StringIO()
        self._write_csv_file(tmp_fd, result)
        self.outzip.writestr("artifacts/%s.csv" % result.artifact_name,
                             tmp_fd.getvalue(),
                             zipfile.ZIP_DEFLATED)


        if self.create_timeline:
            tmp_fd = StringIO.StringIO()
            self._write_csv_file(tmp_fd, self._create_timeline(result))
            self.outzip.writestr("artifacts/%s.timeline.csv" %
                                 result.artifact_name,
                                 tmp_fd.getvalue(),
                                 zipfile.ZIP_DEFLATED)


# Rekall defines a new artifact type.
TYPE_INDICATOR_REKALL = "REKALL_EFILTER"


class _FieldDefinitionValidator(object):
    """Loads and validates fields in a dict.

    We check their name, types and if they are optional according to a template
    in _field_definitions.
    """
    _field_definitions = []

    def _LoadFieldDefinitions(self, data, field_definitions):
        for field in field_definitions:
            name = field["name"]

            default = field.get("default")
            required_type = field.get("type")

            if required_type in (str, unicode):
                required_type = basestring

            if default is None and required_type is not None:
                # basestring cant be instantiated.
                if required_type is basestring:
                    default = ""
                else:
                    default = required_type()

            if required_type is None and default is not None:
                required_type = type(default)

            if not field.get("optional"):
                if name not in data:
                    raise errors.FormatError(
                        u'Missing fields {}.'.format(name))

            value = data.get(name, default)
            if default is not None and not isinstance(value, required_type):
                raise errors.FormatError(
                    u'field {} has type {} should be {}.'.format(
                        name, type(data[name]), required_type))

            if field.get("checker"):
                value = field["checker"](self, data)

            setattr(self, name, value)


class SourceType(_FieldDefinitionValidator):
    """All sources inherit from this."""

    # Common fields for all sources.
    _common_fields = [
        dict(name="type", optional=False),
        dict(name="supported_os", optional=True, type=list,
             default=list(definitions.SUPPORTED_OS)),
    ]

    def __init__(self, source_definition, artifact=None):
        attributes = source_definition["attributes"]
        # The artifact that owns us.
        self.artifact = artifact
        self.source_definition = source_definition
        self.type_indicator = source_definition["type"]
        self._LoadFieldDefinitions(attributes, self._field_definitions)
        self._LoadFieldDefinitions(source_definition, self._common_fields)

    def is_active(self, **_):
        """Indicates if the source is applicable to the environment."""
        return True

    def apply(self, artifact_name=None, fields=None, result_type=None, **_):
        """Generate ArtifactResult instances."""
        return ArtifactResult(artifact_name=artifact_name,
                              result_type=result_type,
                              fields=fields)

# These are the valid types of Rekall images. They can be used to restrict
# REKALL_EFILTER artifacts to specific types of images. The types which end in
# API refer to the API only version of the similar plugins.
REKALL_IMAGE_TYPES = [
    "Windows", "WindowsAPI",
    "Linux", "LinuxAPI",
    "Darwin", "DarwinAPI"
]


class RekallEFilterArtifacts(SourceType):
    """Class to support Rekall Efilter artifact types."""

    allowed_types = {
        "int": int,
        "unicode": unicode,  # Unicode data.
        "str": str, # Used for binary data.
        "float": float,
        "epoch": float, # Dates as epoch timestamps.
        "any": str  # Used for opaque types that can not be further processed.
    }

    _field_definitions = [
        dict(name="query", type=basestring),
        dict(name="query_parameters", default=[], optional=True),
        dict(name="fields", type=list),
        dict(name="type_name", type=basestring),
        dict(name="image_type", type=list, optional=True,
             default=REKALL_IMAGE_TYPES),
    ]

    def __init__(self, source_definition, **kw):
        super(RekallEFilterArtifacts, self).__init__(source_definition, **kw)
        for column in self.fields:
            if "name" not in column or "type" not in column:
                raise errors.FormatError(
                    u"Field definition should have both name and type.")

            mapped_type = column["type"]
            if mapped_type not in self.allowed_types:
                raise errors.FormatError(
                    u"Unsupported type %s." % mapped_type)

    def GetImageType(self, session):
        """Returns one of the standard image types based on the session."""
        result = session.profile.metadata("os").capitalize()

        if session.GetParameter("live_mode") == "API":
            result += "API"

        return result

    def is_active(self, session=None):
        """Determine if this source is active."""
        return (self.image_type and
                self.GetImageType(session) in self.image_type)

    def apply(self, session=None, **kwargs):
        result = super(RekallEFilterArtifacts, self).apply(
            fields=self.fields, result_type=self.type_name, **kwargs)

        if not self.is_active(session):
            return

        search = session.plugins.search(
            query=self.query,
            query_parameters=self.query_parameters)

        for match in search.solve():
            row = {}
            for column in self.fields:
                name = column["name"]
                type = column["type"]
                value = match.get(name)
                if value is None:
                    continue

                row[name] = RekallEFilterArtifacts.allowed_types[
                    type](value)

            result.add_result(**row)

        yield result


class LiveModeSourceMixin(object):
    def is_active(self, session=None):
        """Determine if this source is active."""
        # We are only active in Live mode (API or Memory).
        return (session.GetParameter("live_mode") != None and
                session.profile.metadata("os").capitalize() in
                self.supported_os)


class FileSourceType(LiveModeSourceMixin, SourceType):
    _field_definitions = [
        dict(name="paths", default=[]),
        dict(name="separator", default="/", type=basestring,
             optional=True),
    ]

    # These fields will be present in the ArtifactResult object we return.
    _FIELDS = [
        dict(name="st_mode", type="unicode"),
        dict(name="st_nlink", type="int"),
        dict(name="st_uid", type="unicode"),
        dict(name="st_gid", type="unicode"),
        dict(name="st_size", type="int"),
        dict(name="st_mtime", type="epoch"),
        dict(name="filename", type="unicode"),
    ]

    def apply(self, session=None, **kwargs):
        result = super(FileSourceType, self).apply(
            fields=self._FIELDS, result_type="file_information", **kwargs)

        for hits in session.plugins.glob(
                self.paths, path_sep=self.separator,
                root=self.separator).collect():
            # Hits are FileInformation objects, and we just pick some of the
            # important fields to report.
            info = hits["path"]
            row = {}
            for field in self._FIELDS:
                name = field["name"]
                type = RekallEFilterArtifacts.allowed_types[field["type"]]
                row[name] = type(getattr(info, name))

            result.add_result(**row)

        yield result


class ArtifactGroupSourceType(SourceType):
    _field_definitions = [
        dict(name="names", type=list),
        dict(name="supported_os", optional=True,
             default=definitions.SUPPORTED_OS),
    ]

    def apply(self, collector=None, **_):
        for name in self.names:
            for result in collector.collect_artifact(name):
                yield result

class WMISourceType(LiveModeSourceMixin, SourceType):
    _field_definitions = [
        dict(name="query", type=basestring),
        dict(name="fields", type=list, optional=True, default=[]),
        dict(name="type_name", type=basestring, optional=True),
        dict(name="supported_os", optional=True,
             default=definitions.SUPPORTED_OS),
    ]

    fields = None

    def _guess_returned_fields(self, sample):
        result = []
        for key, value in sample.iteritems():
            field_type = type(value)
            if field_type is int:
                field_type = "int"
            elif field_type is str:
                field_type = "unicode"
            else:
                field_type = "unicode"

            result.append(dict(name=key, type=field_type))
        return result

    def apply(self, session=None, **kwargs):
        result = super(WMISourceType, self).apply(
            result_type=self.type_name, **kwargs)
        wmi = session.plugins.wmi(query=self.query)

        # The wmi plugin may not exist on non-windows systems.
        if wmi == None:
            return

        for collected in wmi.collect():
            match = collected["Result"]
            row = {}
            # If the user did not specify the fields, we must
            # deduce them from the first returned row.
            if not self.fields:
                self.fields = self._guess_returned_fields(match)

            result.fields = self.fields

            for column in self.fields:
                name = column["name"]
                type = column["type"]
                value = match.get(name)
                if value is None:
                    continue

                row[name] = RekallEFilterArtifacts.allowed_types[
                    type](value)

            result.add_result(**row)

        yield result


class RegistryKeySourceType(LiveModeSourceMixin, SourceType):
    _field_definitions = [
        dict(name="keys", default=[]),
        dict(name="supported_os", optional=True,
             default=["Windows"]),
    ]

    _FIELDS = [
        dict(name="st_mtime", type="epoch"),
        dict(name="hive", type="unicode"),
        dict(name="key_name", type="unicode"),
        dict(name="value", type="str"),
        dict(name="value_type", type="str"),
    ]

    def apply(self, session=None, **kwargs):
        result = super(RegistryKeySourceType, self).apply(
            fields=self._FIELDS, result_type="registry_key", **kwargs)

        for hits in session.plugins.glob(
                self.keys, path_sep="\\", filesystem="Reg",
                root="\\").collect():
            # Hits are FileInformation objects, and we just pick some of the
            # important fields to report.
            info = hits["path"]
            row = {}
            for field in self._FIELDS:
                name = field["name"]
                field_type = RekallEFilterArtifacts.allowed_types[field["type"]]
                data = info.get(name)
                if data is not None:
                    row[name] = field_type(data)

            result.add_result(**row)

        yield result


class RegistryValueSourceType(LiveModeSourceMixin, SourceType):
    def CheckKeyValuePairs(self, source):
        key_value_pairs = source["key_value_pairs"]
        for pair in key_value_pairs:
            if (not isinstance(pair, dict) or "key" not in pair or
                "value" not in pair):
                raise errors.FormatError(
                    u"key_value_pairs should consist of dicts with key and "
                    "value items.")

        return key_value_pairs

    _field_definitions = [
        dict(name="key_value_pairs", default=[],
             checker=CheckKeyValuePairs),
        dict(name="supported_os", optional=True,
             default=["Windows"]),
    ]

    _FIELDS = [
        dict(name="st_mtime", type="epoch"),
        dict(name="hive", type="unicode"),
        dict(name="key_name", type="unicode"),
        dict(name="value_name", type="unicode"),
        dict(name="value_type", type="str"),
        dict(name="value", type="str"),
    ]

    def apply(self, session=None, **kwargs):
        result = super(RegistryValueSourceType, self).apply(
            fields=self._FIELDS, result_type="registry_value", **kwargs)
        globs = [u"%s\\%s" % (x["key"], x["value"])
                 for x in self.key_value_pairs]

        for hits in session.plugins.glob(
                globs, path_sep="\\", filesystem="Reg",
                root="\\").collect():
            info = hits["path"]
            row = {}
            for field in self._FIELDS:
                name = field["name"]
                field_type = RekallEFilterArtifacts.allowed_types[field["type"]]
                data = info.get(name)
                if data is not None:
                    row[name] = field_type(data)

            result.add_result(**row)

        yield result


# This lookup table maps between source type name and concrete implementations
# that we support. Artifacts which contain sources which are not implemented
# will be ignored.
SOURCE_TYPES = {
    TYPE_INDICATOR_REKALL: RekallEFilterArtifacts,
    definitions.TYPE_INDICATOR_FILE: FileSourceType,
    definitions.TYPE_INDICATOR_ARTIFACT_GROUP: ArtifactGroupSourceType,
    definitions.TYPE_INDICATOR_WMI_QUERY: WMISourceType,
    definitions.TYPE_INDICATOR_WINDOWS_REGISTRY_KEY: RegistryKeySourceType,
    definitions.TYPE_INDICATOR_WINDOWS_REGISTRY_VALUE: RegistryValueSourceType,
}


class ArtifactDefinition(_FieldDefinitionValidator):
    """The main artifact class."""

    def CheckLabels(self, art_definition):
        """Ensure labels are defined."""
        labels = art_definition.get("labels", [])
        # Keep unknown labels around in case callers want to check for complete
        # label coverage. In most cases it is desirable to allow users to extend
        # labels but when super strict validation is required we want to make
        # sure that users dont typo a label.
        self.undefined_labels = set(labels).difference(definitions.LABELS)
        return labels

    def BuildSources(self, art_definition):
        sources = art_definition["sources"]
        result = []
        self.unsupported_source_types = []
        for source in sources:
            if not isinstance(source, dict):
                raise errors.FormatError("Source is not a dict.")

            source_type_name = source.get("type")
            if source_type_name is None:
                raise errors.FormatError("Source has no type.")

            source_cls = self.source_types.get(source_type_name)
            if source_cls:
                result.append(source_cls(source, artifact=self))
            else:
                self.unsupported_source_types.append(source_type_name)

        if not result:
            if self.unsupported_source_types:
                raise errors.FormatError(
                    "No supported sources: %s" % (
                        self.unsupported_source_types,))

            raise errors.FormatError("No available sources.")

        return result

    def SupportedOS(self, art_definition):
        supported_os = art_definition.get(
            "supported_os", definitions.SUPPORTED_OS)

        undefined_supported_os = set(supported_os).difference(
            definitions.SUPPORTED_OS)

        if undefined_supported_os:
            raise errors.FormatError(
                u'supported operating system: {} '
                u'not defined.'.format(
                    u', '.join(undefined_supported_os)))

        return supported_os

    _field_definitions = [
        dict(name="name", type=basestring),
        dict(name="doc", type=basestring),
        dict(name="labels", default=[],
             checker=CheckLabels, optional=True),
        dict(name="sources", default=[],
             checker=BuildSources),
        dict(name="supported_os",
             checker=SupportedOS, optional=True),
        dict(name="conditions", default=[], optional=True),
        dict(name="returned_types", default=[], optional=True),
        dict(name="provides", type=list, optional=True),
        dict(name="urls", type=list, optional=True)
    ]

    name = "unknown"
    source_types = SOURCE_TYPES

    def __init__(self, data, source_types=None):
        self.source_types = source_types or SOURCE_TYPES
        self.data = data
        try:
            self._LoadDefinition(data)
        except Exception as e:
            exc_info = sys.exc_info()
            raise errors.FormatError(
                "Definition %s: %s" % (self.name, e)), None, exc_info[2]

    def set_implementations(self, source_types):
        return self.__class__(self.data, source_types)

    def _LoadDefinition(self, data):
        if not isinstance(data, dict):
            raise errors.FormatError(
                "Artifact definition must be a dict.")

        different_keys = set(data) - definitions.TOP_LEVEL_KEYS
        if different_keys:
            raise errors.FormatError(u'Undefined keys: {}'.format(
                different_keys))

        self._LoadFieldDefinitions(data, self._field_definitions)


class ArtifactDefinitionProfileSectionLoader(obj.ProfileSectionLoader):
    """Loads artifacts from the artifact profiles."""
    name = "$ARTIFACTS"

    def LoadIntoProfile(self, session, profile, art_definitions):
        for definition in art_definitions:
            try:
                profile.AddDefinition(definition)
            except errors.FormatError as e:
                session.logging.debug(
                    "Skipping Artifact %s: %s", definition.get("name"), e)

        return profile


class ArtifactProfile(obj.Profile):
    """A profile containing artifact definitions."""

    # This will contain the definitions.
    def __init__(self, *args, **kwargs):
        super(ArtifactProfile, self).__init__(*args, **kwargs)
        self.definitions = []
        self.definitions_by_name = {}

    def AddDefinition(self, definition):
        """Add a new definition from a dict."""
        self.definitions.append(definition)
        self.definitions_by_name[definition["name"]] = definition

    def GetDefinitionByName(self, name, source_types=None):
        if source_types is None:
            source_types = SOURCE_TYPES

        definition = self.definitions_by_name[name]
        return ArtifactDefinition(definition, source_types)

    def GetDefinitions(self, source_types=None):
        if source_types is None:
            source_types = SOURCE_TYPES

        for definition in self.definitions:
            try:
                yield ArtifactDefinition(definition, source_types)
            except errors.FormatError:
                pass


class ArtifactsCollector(plugin.TypedProfileCommand,
                         plugin.Command):
    """Collects artifacts."""

    name = "artifact_collector"

    __args = [
        dict(name="artifacts", positional=True, required=True,
             type="ArrayStringParser",
             help="A list of artifact names to collect."),

        dict(name="artifact_files", type="ArrayStringParser",
             help="A list of additional yaml files to load which contain "
             "artifact definitions."),

        dict(name="definitions", type="ArrayStringParser",
             help="An inline artifact definition in yaml format."),

        dict(name="create_timeline", type="Bool", default=False,
             help="Also generate a timeline file."),

        dict(name="copy_files", type="Bool", default=False,
             help="Copy files into the output."),

        dict(name="writer", type="Choices",
             choices=lambda: (
                 x.name for x in BaseArtifactResultWriter.classes.values()),
             help="Writer for artifact results."),

        dict(name="output_path",
             help="Path suitable for dumping files."),
    ]

    table_header = [
        dict(name="divider", type="Divider"),
        dict(name="result"),
    ]

    table_options = dict(
        suppress_headers=True
    )

    def column_types(self):
        return dict(path=common.FileInformation(filename="/etc"))

    def __init__(self, *args, **kwargs):
        super(ArtifactsCollector, self).__init__(*args, **kwargs)
        self.artifact_profile = self.session.LoadProfile("artifacts")

        extra_definitions = [
            open(x).read() for x in self.plugin_args.artifact_files]
        extra_definitions.extend(self.plugin_args.definitions or [])

        # Make a copy of the artifact registry.
        if extra_definitions:
            self.artifact_profile = self.artifact_profile.copy()

            for definition in extra_definitions:
                for definition_data in yaml.safe_load_all(definition):
                    self.artifact_profile.AddDefinition(definition_data)

        self.seen = set()
        self.supported_os = self.get_supported_os(self.session)
        if self.supported_os is None:
            raise plugin.PluginError(
                "Unable to determine running environment.")

        # Make sure the args make sense.
        if self.plugin_args.output_path is None:
            if self.plugin_args.copy_files:
                raise plugin.PluginError(
                    "Can only copy files when an output file is specified.")
            if self.plugin_args.create_timeline:
                raise plugin.PluginError(
                    "Can only create timelines when an output file "
                    "is specified.")

    @classmethod
    def get_supported_os(cls, session):
        # Determine which context we are running in. If we are running in live
        # mode, we use the platform to determine the supported OS, otherwise we
        # determine it from the profile.
        if session.GetParameter("live"):
            return platform.system()
        elif session.profile.metadata("os") == "linux":
            return "Linux"

        elif session.profile.metadata("os") == "windows":
            return "Windows"

        elif session.profile.metadata("os") == "darwin":
            return "Darwin"

    def _evaluate_conditions(self, conditions):
        # TODO: Implement an expression parser for these. For now we just return
        # True always.
        return True

    def collect_artifact(self, artifact_name):
        if artifact_name in self.seen:
            return

        self.seen.add(artifact_name)

        try:
            definition = self.artifact_profile.GetDefinitionByName(
                artifact_name)
        except KeyError:
            self.session.logging.error("Unknown artifact %s" % artifact_name)
            return

        # This artifact is not for us.
        if self.supported_os not in definition.supported_os:
            self.session.logging.debug(
                "Skipping artifact %s: Supported OS: %s, but we are %s",
                definition.name, definition.supported_os,
                self.supported_os)
            return

        if not self._evaluate_conditions(definition.conditions):
            return

        yield dict(divider="Artifact: %s" % definition.name)

        for source in definition.sources:
            # This source is not for us.
            if not source.is_active(session=self.session):
                continue

            for result in source.apply(
                    artifact_name=definition.name,
                    session=self.session,
                    collector=self):
                if isinstance(result, dict):
                    yield result
                else:
                    yield dict(result=result)

    def collect(self):
        # Figure out a sensible default for the output writer.
        if (self.plugin_args.output_path is not None and
            self.plugin_args.writer is None):

            if os.path.isdir(self.plugin_args.output_path):
                self.plugin_args.writer = "Directory"
            else:
                self.plugin_args.writer = "Zip"

        if self.plugin_args.writer:
            impl = BaseArtifactResultWriter.ImplementationByName(
                self.plugin_args.writer)
            with impl(session=self.session,
                      copy_files=self.plugin_args.copy_files,
                      create_timeline=self.plugin_args.create_timeline,
                      output=self.plugin_args.output_path) as writer:
                for x in self._collect(writer=writer):
                    yield x
        else:
            for x in self._collect():
                yield x

    def _collect(self, writer=None):
        for artifact_name in self.plugin_args.artifacts:
            for hit in self.collect_artifact(artifact_name):
                if "result" in hit and writer:
                    writer.write_result(hit["result"])
                yield hit

class ArtifactsView(plugin.TypedProfileCommand,
                    plugin.Command):
    name = "artifact_view"

    __args = [
        dict(name="artifacts", type="ArrayStringParser", positional=True,
             help="A list of artifacts to display")
    ]

    table_header = [
        dict(name="divider", type="Divider"),
        dict(name="Message")
    ]

    def collect(self):
        artifact_profile = self.session.LoadProfile("artifacts")
        for artifact in self.plugin_args.artifacts:
            definition = artifact_profile.definitions_by_name.get(artifact)
            if definition:
                yield dict(divider=artifact)
                yield dict(Message=yaml_utils.safe_dump(definition))


class ArtifactsList(plugin.TypedProfileCommand,
                    plugin.Command):
    """List details about all known artifacts."""

    name = "artifact_list"

    __args = [
        dict(name="regex", type="RegEx",
             default=".",
             help="Filter the artifact name."),
        dict(name="supported_os", type="ArrayStringParser", required=False,
             help="If specified show for these OSs, otherwise autodetect "
             "based on the current image."),
        dict(name="labels", type="ArrayStringParser",
             help="Filter by these labels."),
        dict(name="all", type="Bool",
             help="Show all artifacts."),
    ]

    table_header = [
        dict(name="Name", width=30),
        dict(name="OS", width=8),
        dict(name="Labels", width=20),
        dict(name="Types", width=20),
        dict(name="Description", width=50),
    ]

    def collect(self):
        # Empty means autodetect based on the image.
        if not self.plugin_args.supported_os:
            supported_os = set([
                ArtifactsCollector.get_supported_os(self.session)])
        else:
            supported_os = set(self.plugin_args.supported_os)

        for definition in self.session.LoadProfile(
                "artifacts").GetDefinitions():
            if (not self.plugin_args.all and
                not supported_os.intersection(definition.supported_os)):
                continue

            # Determine the type:
            types = set()
            for source in definition.sources:
                if self.plugin_args.all or source.is_active(
                        session=self.session):
                    types.add(source.type_indicator)

                    if self.plugin_args.regex.match(definition.name):
                        yield (definition.name, definition.supported_os,
                               definition.labels, sorted(types), definition.doc)


class ArtifactResult_TextObjectRenderer(text.TextObjectRenderer):
    renders_type = "ArtifactResult"

    def render_row(self, target, **_):
        column_names = [x["name"] for x in target.fields]
        table = text.TextTable(
            columns=target.fields,
            renderer=self.renderer,
            session=self.session)

        if not target.results:
            return text.Cell("")

        result = [
            text.JoinedCell(*[text.Cell(x) for x in column_names]),
            text.JoinedCell(*[text.Cell("-" * len(x)) for x in column_names])]

        for row in target.results:
            ordered_row = []
            for column in column_names:
                ordered_row.append(row.get(column))

            result.append(table.get_row(*ordered_row))

        result = text.StackedCell(*result)
        return result


class ArtifactResult_DataExportObjectRenderer(
        json_renderer.StateBasedObjectRenderer):
    renders_type = "ArtifactResult"
    renderers = ["DataExportRenderer"]

    def GetState(self, item, **_):
        return dict(artifact_name=item.artifact_name,
                    result_type=item.result_type,
                    fields=item.fields,
                    results=item.results)
