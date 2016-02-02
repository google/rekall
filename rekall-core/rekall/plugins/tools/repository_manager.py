# Rekall Memory Forensics
# Copyright 2015 Google Inc. All Rights Reserved.
#
# Author: Michael Cohen scudette@google.com
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

"""
This plugin manages the profile repository.

"""
import json
import os
import yaml

from rekall import io_manager
from rekall import plugin
from rekall import registry
from rekall import testlib
from rekall import utils


class RepositoryManager(io_manager.DirectoryIOManager):
    """We manage the repository using YAML.

    YAML is more user friendly than JSON.
    """

    def Encoder(self, data, **_):
        return utils.PPrint(data)

    def Decoder(self, raw):
        return yaml.safe_load(raw)


class RepositoryPlugin(object):
    """A plugin to manage a type of profile in the repository."""
    __metaclass__ = registry.MetaclassRegistry

    def __init__(self, session=None, **kwargs):
        """Instantiate the plugin with the provided kwargs."""
        self.args = utils.AttributeDict(kwargs)
        self.session = session

    def TransformProfile(self, profile):
        """Transform the profile according to the specified transforms."""
        transforms = self.args.transforms or {}
        for transform, args in transforms.items():
            if transform == "merge":
                profile["$MERGE"] = args
            else:
                raise RuntimeError("Unknown transform %s" % transform)

        return profile

    def Build(self, renderer):
        """Implementation of the build routine."""


class WindowsGUIDProfile(RepositoryPlugin):
    """Manage a Windows profile from the symbol server."""

    def _RunPlugin(self, plugin_name, **args):
        # Run the plugin inline.
        self.session.RunPlugin(plugin_name, **args)

    def FetchPDB(self, temp_dir, guid, pdb_filename):
        self._RunPlugin("fetch_pdb", pdb_filename=pdb_filename,
                        guid=guid, dump_dir=temp_dir)

        data = open(os.path.join(temp_dir, pdb_filename)).read()
        repository = self.args.repository

        repository.StoreData("src/pdb/%s.pdb" % guid, data, raw=True)

    def ParsePDB(self, temp_dir, guid, original_pdb_filename):
        repository = self.args.repository
        data = repository.GetData("src/pdb/%s.pdb" % guid, raw=True)
        pdb_filename = os.path.join(temp_dir, guid + ".pdb")
        output_filename = os.path.join(temp_dir, guid)
        with open(pdb_filename, "wb") as fd:
            fd.write(data)

        profile_class = (self.args.profile_class or
                         original_pdb_filename.capitalize())
        self._RunPlugin(
            "parse_pdb", pdb_filename=pdb_filename, profile_class=profile_class,
            output=output_filename)

        profile_data = json.loads(open(output_filename, "rb").read())
        profile_data = self.TransformProfile(profile_data)
        repository.StoreData("%s/%s" % (self.args.profile_name, guid),
                             profile_data)

    def BuildIndex(self):
        repository = self.args.repository
        # Rebuild the index.
        with utils.TempDirectory() as temp_dir:
            output_filename = os.path.join(temp_dir, "index")
            spec_filename = os.path.join(temp_dir, "index.yaml")

            with open(spec_filename, "wb") as fd:
                fd.write(repository.GetData(self.args.index, raw=True))

            self._RunPlugin("build_index",
                            output=output_filename,
                            spec=spec_filename)

            repository.StoreData("%s/index" % self.args.profile_name,
                                 json.load(open(output_filename)))

    def Build(self, renderer):
        repository = self.args.repository
        guid_file = self.args.repository.GetData(self.args.guids)

        changed_files = False
        for pdb_filename, guids in guid_file.iteritems():
            for guid in guids:
                # If the profile exists in the repository continue.
                if repository.Metadata(
                        "%s/%s" % (self.args.profile_name, guid)):
                    continue

                renderer.format("Building profile {0}/{1}\n",
                                self.args.profile_name, guid)

                # Otherwise build it.
                changed_files = True

                with utils.TempDirectory() as temp_dir:
                    # Do we need to fetch the pdb file?
                    if not repository.Metadata("src/pdb/%s.pdb" % guid):
                        self.FetchPDB(temp_dir, guid, pdb_filename)

                    self.ParsePDB(temp_dir, guid, pdb_filename)

        if changed_files and self.args.index:
            renderer.format("Building index for profile {0} from {1}\n",
                            self.args.profile_name, self.args.index)

            self.BuildIndex()


class CopyAndTransform(RepositoryPlugin):
    """A profile processor which copies and transforms."""

    def Build(self, renderer):
        repository = self.args.repository
        profile_metadata = repository.Metadata(self.args.profile_name)
        source_metadata = repository.Metadata(self.args.source)
        if not profile_metadata or (
                source_metadata["LastModified"] >
                profile_metadata["LastModified"]):
            data = repository.GetData(self.args.source)

            # Transform the data as required.
            data = self.TransformProfile(data)
            repository.StoreData(self.args.profile_name, utils.PPrint(data),
                                 raw=True)
            renderer.format("Building profile {0} from {1}\n",
                            self.args.profile_name, self.args.source)


class OSXProfile(RepositoryPlugin):
    """Build OSX Profiles."""

    def Build(self, renderer):
        repository = self.args.repository
        for source in self.args.sources:
            profile_name = "OSX/%s" % source.split("/")[-1]
            profile_metadata = repository.Metadata(profile_name)

            # Profile does not exist - rebuild it.
            if not profile_metadata:
                data = json.loads(repository.GetData(source, raw=True))

                # Transform the data as required.
                data = self.TransformProfile(data)
                repository.StoreData(profile_name, utils.PPrint(data),
                                     raw=True)
                renderer.format("Building profile {0} from {1}\n",
                                profile_name, source)


class ManageRepository(plugin.Command):
    """Manages the profile repository."""

    name = "manage_repo"

    @classmethod
    def args(cls, parser):
        super(ManageRepository, cls).args(parser)

        parser.add_argument(
            "path_to_repository", default=".",
            help="The path to the profile repository")

    def __init__(self, command=None, path_to_repository=None, **kwargs):
        super(ManageRepository, self).__init__(**kwargs)
        self.command = command
        self.path_to_repository = os.path.abspath(path_to_repository)

        # Check if we can load the repository config file.
        self.repository = RepositoryManager(
            self.path_to_repository, session=self.session)

        self.config_file = self.repository.GetData("config.yaml")

    def render(self, renderer):
        for profile_name, kwargs in self.config_file.iteritems():
            handler_type = kwargs.pop("type", None)
            if not handler_type:
                raise RuntimeError(
                    "Unspecified repository handler for profile %s" %
                    profile_name)

            handler_cls = RepositoryPlugin.classes.get(handler_type)
            if handler_cls is None:
                raise RuntimeError(
                    "Unknown repository handler %s" % handler_type)

            handler = handler_cls(
                session=self.session, repository=self.repository,
                profile_name=profile_name, **kwargs)
            handler.Build(renderer)


class TestManageRepository(testlib.DisabledTest):
    """Dont run automated tests for this tool."""
