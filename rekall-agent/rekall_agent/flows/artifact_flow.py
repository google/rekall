# Rekall Memory Forensics
#
# Copyright 2016 Google Inc. All Rights Reserved.
#
# Authors:
# Michael Cohen <scudette@google.com>
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

"""Artifact Collector flow.

We create the artifacts on the server and simply run them on the clients. The
artifact flow simply launches a series of client actions based on the requested
artifacts, and writes the results to the client's bucket namespace.

NOTE: This implementation is currently similar but different from the one in
rekall.plugins.response.forensic_artifacts.

"""

__author__ = "Michael Cohen <scudette@google.com>"
from artifacts import definitions

from rekall.plugins.response import forensic_artifacts
from rekall_agent import flow
from rekall_agent.flows import find


class FileSourceType(forensic_artifacts.SourceType):
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

    def actions(self, flow_obj, download=False, name=None, **_):
        """Generate actions for the client."""
        # Create the new flow based on the current flow. We do not actually
        # launch it, but just collect its actions.
        subflow = flow_obj.cast(find.FileFinderFlow)

        subflow.globs = self.paths
        subflow.download = download
        if name is None:
            name = self.artifact.name

        subflow.set_collection_name("{flow_id}/%s" % name)

        for action in subflow.generate_actions():
            yield action


SOURCE_TYPES = {
    definitions.TYPE_INDICATOR_FILE: FileSourceType,
}


class Artifact(flow.Flow):
    """Launch artifacts on the client."""
    schema = [
        dict(name="artifacts", repeated=True, private=True, user=True,
             doc="The list of artifacts to launch."),
        dict(name="copy_files", type="bool", user=True,
             doc="Should we also download the files."),
    ]

    def generate_actions(self):
        self._artifact_profile = self._session.LoadProfile("artifacts")
        self._collected_artifacts = []

        for artifact_name in self.artifacts:
            try:
                definition = self._artifact_profile.GetDefinitionByName(
                    artifact_name, source_types=SOURCE_TYPES)
            except KeyError:
                self._session.logging.error(
                    "Unknown artifact %s" % artifact_name)
                continue

            for source in definition.sources:
                for action in source.actions(self, download=self.copy_files):
                    yield action
