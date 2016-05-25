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
import multiprocessing
import subprocess
import sys
import yaml

from rekall import io_manager
from rekall import plugin
from rekall import registry
from rekall import threadpool
from rekall import testlib
from rekall import utils


NUMBER_OF_CORES = multiprocessing.cpu_count()


class BuilderError(Exception):
    """Raised when the builder failed."""


class RepositoryManager(io_manager.DirectoryIOManager):
    """We manage the repository using YAML.

    YAML is more user friendly than JSON.
    """
    # Do not include src files in the inventory.
    EXCLUDED_PATH_PREFIX = ["src"]

    def Encoder(self, data, **options):
        if options.get("raw"):
            return utils.SmartStr(data)

        # If the user specifically wants to encode in yaml, then do so.
        if options.get("yaml"):
            return yaml.safe_dump(data, default_flow_style=False)

        return utils.PPrint(data)

    def Decoder(self, raw):
        try:
            # First try to load it with json because it is way faster.
            return super(RepositoryManager, self).Decoder(raw)
        except ValueError:
            # If that does not work, try to load it with yaml.
            return yaml.safe_load(raw)

    def _StoreData(self, name, to_write, **options):
        # The user wants to store a yaml file, we make it uncompressed.
        if options.get("yaml"):
            options["uncompressed"] = True

        return super(RepositoryManager, self)._StoreData(
            name, to_write, **options)


class RepositoryPlugin(object):
    """A plugin to manage a type of profile in the repository."""
    __metaclass__ = registry.MetaclassRegistry

    def __init__(self, session=None, **kwargs):
        """Instantiate the plugin with the provided kwargs."""
        self.args = utils.AttributeDict(kwargs)
        self.session = session
        self.pool = threadpool.ThreadPool(self.args.processes)

    def TransformProfile(self, profile):
        """Transform the profile according to the specified transforms."""
        transforms = self.args.transforms or {}
        for transform, args in transforms.items():
            if transform == "merge":
                profile["$MERGE"] = args
            else:
                raise RuntimeError("Unknown transform %s" % transform)

        return profile

    def BuildIndex(self):
        repository = self.args.repository
        for index in self.args.index:
            spec = repository.GetData(index["src"])

            built_index = self.session.plugins.build_index(
                manager=repository).build_index(spec)

            repository.StoreData(index["dest"], built_index)

    def LaunchPlugin(self, plugin_name, *pos, **kwargs):
        """Runs a plugin in another process."""
        subprocess.check_call(
            [sys.executable, plugin_name] + pos +
            ["--%s='%s'" % (k, v) for k, v in kwargs.iteritems()])

    def LaunchBuilder(self, *args):
        """Relaunch this builder with the provided parameters."""
        executable = self.args.executable
        if executable is None:
            executable = sys.argv[0]
        cmdline = [executable]

        # We are launched with the python executable.
        if "python" in executable:
            cmdline.append(sys.argv[1])

        cmdline.extend(["manage_repo", "--path_to_repository",
                        self.args.repository.location])
        cmdline.append(self.args.profile_name)
        cmdline.extend(args)

        pipe = subprocess.Popen(cmdline, stderr=subprocess.PIPE)
        _, stderr_text = pipe.communicate()
        if pipe.returncode != 0:
            error_message = stderr_text.strip().splitlines()[-1]
            raise BuilderError(error_message)

    def Build(self, renderer):
        """Implementation of the build routine."""


class WindowsGUIDProfile(RepositoryPlugin):
    """Manage a Windows profile from the symbol server."""

    def FetchPDB(self, guid, pdb_filename):
        repository = self.args.repository
        fetch_pdb = self.session.plugins.fetch_pdb()
        data = fetch_pdb.FetchPDBFile(pdb_filename=pdb_filename, guid=guid)
        repository.StoreData("src/pdb/%s.pdb" % guid, data, raw=True)

    def ParsePDB(self, guid, original_pdb_filename):
        repository = self.args.repository
        data = repository.GetData("src/pdb/%s.pdb" % guid, raw=True)
        profile_class = (self.args.profile_class or
                         original_pdb_filename.capitalize())

        with utils.TempDirectory() as temp_dir:
            pdb_filename = os.path.join(temp_dir, guid + ".pdb")
            with open(pdb_filename, "wb") as fd:
                fd.write(data)

            parse_pdb = self.session.plugins.parse_pdb(
                pdb_filename=pdb_filename,
                profile_class=profile_class)

            profile_data = json.loads(str(parse_pdb))

        profile_data = self.TransformProfile(profile_data)
        repository.StoreData("%s/%s" % (self.args.profile_name, guid),
                             profile_data)

    def ProcessPdb(self, guid, pdb_filename):
        self.session.logging.info(
            "Building profile %s/%s\n", self.args.profile_name, guid)

        # Do we need to fetch the pdb file?
        repository = self.args.repository
        if not repository.Metadata("src/pdb/%s.pdb" % guid):
            self.FetchPDB(guid, pdb_filename)

        self.ParsePDB(guid, pdb_filename)

    def Build(self, renderer, *args):
        self.guid_file = self.args.repository.GetData(self.args.guids)
        if not args:
            command = "build_all"
        else:
            command = args[0]
            args = args[1:]

        self.ParseCommand(renderer, command, args)

    def _FindPDBFilename(self, guid):
        possible_guids = self.args.possible_guid_filenames
        if not possible_guids:
            possible_guids = [self.args.profile_name + ".pdb"]

        for guid_file in possible_guids:
            try:
                self.FetchPDB(guid, guid_file)
                return guid_file
            except Exception:
                continue

        raise ValueError("Unknown pdb filename for guid %s" % guid)

    def _DecodeGUIDFromArg(self, arg):
        if "/" in arg:
            pdb_filename, guid = arg.split("/")
        else:
            guid = arg
            pdb_filename = self._FindPDBFilename(arg)

        if not pdb_filename.endswith("pdb") or len(guid) != 33:
            raise ValueError("Invalid GUID or pdb filename - e.g. "
                             "ntkrnlmp.pdb/00625D7D36754CBEBA4533BA9A0F3FE22.")

        return pdb_filename, guid

    def _AddGUIDs(self, args):
        repository = self.args.repository
        guid_file = self.args.repository.GetData(self.args.guids)
        existing_guids = dict((x, set(y)) for x, y in guid_file.iteritems())

        for arg in args:
            pdb_filename, guid = self._DecodeGUIDFromArg(arg)
            self.session.logging.info(
                "Adding GUID %s %s" % (pdb_filename, guid))
            existing_guids.setdefault(pdb_filename, set()).add(guid)

        new_guids = dict((k, sorted(v)) for k, v in existing_guids.iteritems())
        repository.StoreData(self.args.guids, new_guids, yaml=True)

    def ParseCommand(self, renderer, command, args):
        if command == "build":
            for arg in args:
                pdb_filename, guid = self._DecodeGUIDFromArg(arg)
                self.ProcessPdb(guid, pdb_filename)

        elif command == "build_all":
            self.BuildAll(renderer)

        elif command == "add_guid":
            self._AddGUIDs(args)
            self.BuildAll(renderer)

        else:
            raise RuntimeError(
                "Unknown command for %s" % self.__class__.__name__)

    def BuildAll(self, renderer):
        repository = self.args.repository
        guid_file = self.args.repository.GetData(self.args.guids)
        rejects_filename = self.args.guids + ".rejects"
        rejects = self.args.repository.GetData(rejects_filename, default={})
        reject_len = len(rejects)

        try:
            changed_files = set()
            for pdb_filename, guids in guid_file.iteritems():
                for guid in guids:
                    if guid in rejects:
                        continue

                    # If the profile exists in the repository continue.
                    if repository.Metadata(
                            "%s/%s" % (self.args.profile_name, guid)):
                        continue

                    def Reject(e, guid=guid, changed_files=changed_files):
                        print "GUID %s rejected: %s" % (guid, e)
                        rejects[guid] = str(e)
                        changed_files.remove(guid)

                    # Otherwise build it.
                    changed_files.add(guid)
                    self.pool.AddTask(
                        self.LaunchBuilder,
                        ("build", "%s/%s" % (pdb_filename, guid)),
                        on_error=Reject)

            self.pool.Stop()

            if changed_files and self.args.index or self.args.force_build_index:
                renderer.format("Building index for profile {0} from {1}\n",
                                self.args.profile_name, self.args.index)

                self.BuildIndex()

        finally:
            if len(rejects) != reject_len:
                repository.StoreData(
                    rejects_filename, utils.PPrint(rejects), raw=True)

            renderer.format("Updating inventory.\n")
            repository.StoreData("inventory", repository.RebuildInventory())


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
        changed_files = False
        for source in self.args.sources:
            profile_name = "OSX/%s" % source.split("/")[-1]
            profile_metadata = repository.Metadata(profile_name)

            # Profile does not exist - rebuild it.
            if not profile_metadata:
                data = repository.GetData(source)

                # Transform the data as required.
                data = self.TransformProfile(data)
                repository.StoreData(profile_name, utils.PPrint(data),
                                     raw=True)
                renderer.format("Building profile {0} from {1}\n",
                                profile_name, source)
                changed_files = True

        if changed_files and self.args.index or self.args.force_build_index:
            renderer.format("Building index for profile {0} from {1}\n",
                            self.args.profile_name, self.args.index)

            self.BuildIndex()


class LinuxProfile(RepositoryPlugin):
    """Build Linux profiles."""

    def Build(self, renderer):
        """Linux profile location"""
        convert_profile = self.session.plugins.convert_profile(
            session=self.session,
            source="/dev/null",
            out_file="dummy file")  # We don't really output the profile.

        changed_files = False
        total_profiles = 0
        new_profiles = 0

        for source_profile in self.args.repository.ListFiles():
            # Find all source profiles.
            if (source_profile.startswith("src/Linux") and
                    source_profile.endswith(".zip")):

                total_profiles += 1
                profile_id = source_profile.lstrip("src/").rstrip(".zip")

                # Skip already built profiles.
                if self.args.repository.Metadata(profile_id):
                    continue

                # Convert the profile
                self.session.report_progress(
                    "Found new raw Linux profile %s. Converting...", profile_id)
                self.session.logging.info(
                    "Found new raw Linux profile %s", profile_id)

                profile_fullpath = self.args.repository.GetAbsolutePathName(
                    source_profile)
                profile = convert_profile.ConvertProfile(
                    io_manager.Factory(
                        profile_fullpath, session=self.session, mode="r"))
                if not profile:
                    self.session.logging.info(
                        "Skipped %s, Unable to convert to a Rekall profile.",
                        profile_fullpath)
                    continue

                # Add profile to the repository and the inventory
                self.args.repository.StoreData(profile_id, profile)
                new_profiles += 1
                changed_files = True

        self.session.logging.info("Found %d profiles. %d are new.",
                                  total_profiles, new_profiles)

        # Now rebuild the index
        if changed_files and self.args.index or self.args.force_build_index:
            self.BuildIndex()


class ManageRepository(plugin.Command):
    """Manages the profile repository."""

    name = "manage_repo"

    @classmethod
    def args(cls, parser):
        super(ManageRepository, cls).args(parser)
        parser.add_argument(
            "-e", "--executable",
            default=None,
            help="The path to the rekall binary. This is used for "
            "spawning multiple processes.")

        parser.add_argument(
            "--processes", default=NUMBER_OF_CORES, type="IntParser",
            help="Number of concurrent workers.")

        parser.add_argument(
            "--path_to_repository", default=".",
            help="The path to the profile repository")

        parser.add_argument(
            "--force_build_index", type="Boolean", default=False,
            help="Forces building the index.")

        parser.add_argument(
            "build_target", type="StringParser", required=False,
            help="A single target to build.")

        parser.add_argument(
            "builder_args", type="ArrayStringParser", required=False,
            help="Optional args for the builder.")

    def __init__(self, command=None, path_to_repository=None,
                 build_target=None, force_build_index=False,
                 builder_args=None, session=None, **kwargs):
        super(ManageRepository, self).__init__(session=session)
        self.command = command
        self.builder_kwargs = kwargs
        self.path_to_repository = os.path.abspath(path_to_repository)
        self.build_target = build_target
        self.force_build_index = force_build_index
        self.builder_args = builder_args or []

        # Check if we can load the repository config file.
        self.repository = RepositoryManager(
            self.path_to_repository, session=self.session)

        self.config_file = self.repository.GetData("config.yaml")

    def render(self, renderer):
        for profile_name, kwargs in self.config_file.iteritems():
            # Inject args from the commandline into the builder args.
            kwargs.update(self.builder_kwargs)
            if self.build_target and profile_name != self.build_target:
                continue

            self.session.logging.info("Building profiles for %s", profile_name)
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
                profile_name=profile_name,
                force_build_index=self.force_build_index,
                **kwargs)
            handler.Build(renderer, *self.builder_args)


class TestManageRepository(testlib.DisabledTest):
    """Dont run automated tests for this tool."""
