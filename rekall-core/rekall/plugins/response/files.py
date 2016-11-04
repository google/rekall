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

"""This module adds arbitrary file reading to Rekall."""

__author__ = "Michael Cohen <scudette@google.com>"
import fnmatch
import hashlib
import itertools
import platform
import re
import os

from rekall import plugin
from rekall import utils
from rekall.plugins.response import common


BUFFER_SIZE = 10 * 1024 * 1024


class IRFind(common.AbstractIRCommandPlugin):
    """List files recursively from a root path."""
    name = "find"

    __args = [
        dict(name="root", positional=True,
             help="The root directory to start search from.")
    ]

    table_header = [
        dict(name="Perms", type="Permissions", width=16),
        dict(name="Size", align="r", width=10),
        dict(name="Path"),
    ]

    def collect(self):
        for root, dirs, files in os.walk(self.plugin_args.root):
            for d in dirs + files:
                full_path = os.path.join(root, d)
                result = common.FileFactory(full_path, session=self.session)
                if result:
                    yield (result.st_mode, result.st_size, result)


class IRStat(common.AbstractIRCommandPlugin):
    name = "stat"

    __args = [
        dict(name="paths", positional=True, type="Array",
             help="Paths to hash."),
    ]

    table_header = [
        dict(name="Perms", type="Permissions", width=16),
        dict(name="Size", align="r", width=10),
        dict(name="Path"),
    ]

    def collect(self):
        for full_path in self.plugin_args.paths:
            result = common.FileFactory(full_path, session=self.session)
            if result:
                yield dict(Perms=result.st_mode, Size=result.st_size,
                           Path=result)


class Hash(object):
    """A class to hold a hash value."""
    def __init__(self, type="md5", value=None):
        self.type = type
        self.value = value

    def __str__(self):
        return "%s:%s" % (self.type, self.value.encode("hex"))


class IRHash(common.AbstractIRCommandPlugin):
    name = "hash"

    __args = [
        dict(name="paths", positional=True, type="Array",
             help="Paths to hash."),
        dict(name="hash", type="ChoiceArray", default=["sha1"],
             choices=["md5", "sha1", "sha256"],
             help="One or more hashes to calculate.")
    ]

    table_header = [
        dict(name="Hashes", width=72),
        dict(name="Path", type="FileInformation"),
    ]

    def calculate_hashes(self, hashes, file_info):
        hashers = dict((name, getattr(hashlib, name)()) for name in hashes)
        fd = file_info.open()
        while 1:
            data = fd.read(BUFFER_SIZE)
            if not data:
                break

            for hasher in hashers.values():
                hasher.update(data)

        return [Hash(type=name, value=hasher.digest())
                for name, hasher in hashers.iteritems()]

    def collect(self):
        for path in self.plugin_args.paths:
            file_info = common.FileFactory(path)
            if not file_info.st_mode.is_dir():
                yield dict(
                    Hashes=self.calculate_hashes(
                        self.plugin_args.hash, file_info),
                    Path=file_info)


class Component(object):
    def __init__(self, session, component=None, cache=None):
        self.session = session
        self.component = component
        self.component_cache = cache

    def stat(self, path):
        key = unicode(path)
        try:
            return self.component_cache[key]
        except KeyError:
            stat = common.FileFactory(path)
            self.component_cache.Put(key, stat)

            return stat

    def __eq__(self, other):
        return unicode(self) == unicode(other)

    def __hash__(self):
        return hash(unicode(self))

    def __str__(self):
        return "%s:%s" % (self.__class__.__name__, self.component)


class LiteralComponent(Component):

    def case_insensitive_filesystem(self):
        if platform.system() == "Windows":
            return True

        return False

    def filter(self, path):
        # For case insensitive filesystems we can just try to open the
        # component.
        if self.case_insensitive_filesystem():
            result_pathspec = path.add(self.component)
            stat = self.stat(result_pathspec)
            if stat:
                return [stat.filename]
            else:
                return []

        # Since we must match a case insensitve filename we need to
        # list all the files and find the best match.
        stat = common.FileFactory(path)
        if not stat:
            return []

        children = {}
        for x in stat.list_names():
            children.setdefault(x.lower(), []).append(x)

        return [stat.filename.add(x)
                for x in children.get(self.component.lower(), [])]


class RegexComponent(Component):
    def __init__(self, *args, **kwargs):
        super(RegexComponent, self).__init__(*args, **kwargs)
        self.component_re = re.compile(self.component, re.I)

    def filter(self, path):
        stat = self.stat(path)
        if not stat:
            return

        if stat.st_mode.is_dir() and not stat.st_mode.is_link():
            self.session.report_progress("Searching %s", path)
            for basename in stat.list_names():
                if self.component_re.match(basename):
                    yield stat.filename.add(basename)


class RecursiveComponent(RegexComponent):
    def __init__(self, depth=3, **kwargs):
        super(RecursiveComponent, self).__init__(**kwargs)
        self.depth = depth

    def filter(self, path, depth=0):
        self.session.report_progress("Recursing into %s", path)

        # TODO: Deal with cross devices.
        if depth >= self.depth:
            return

        stat = self.stat(path)
        if not stat:
            return

        # Do not follow symlinks.
        if stat.st_mode.is_dir() and not stat.st_mode.is_link():
            # The top level counts as a hit, so that e.g. /**/*.txt
            # matches /foo.txt as well.
            if depth == 0:
                yield stat.filename

            for basename in stat.list_names():
                if (self.component_re.match(basename) and
                    not stat.st_mode.is_link()):
                    subdir = stat.filename.add(basename)
                    yield subdir

                    for subitem in self.filter(subdir, depth+1):
                        yield subitem


class IRGlob(common.AbstractIRCommandPlugin):
    """Search for files by filename glob.

    This code roughly based on the Glob flow in GRR.
    """

    name = "glob"

    __args = [
        dict(name="globs", positional=True, type="ArrayString",
             help="List of globs to return."),
        dict(name="root",
             help="Root directory to glob from."),
        dict(name="case_insensitive", default=True, type="Bool",
             help="Globs will be case insensitive."),
        dict(name="path_sep",
             help="Path separator character (/ or \\)"),
        dict(name="filesystem", choices=common.FILE_SPEC_DISPATCHER,
             type="Choices", default="API",
             help="The virtual filesystem implementation to glob in.")
    ]

    table_header = [
        dict(name="path", type="FileInformation"),
    ]

    def column_types(self):
        return dict(path=common.FileInformation(filename="/etc"))

    INTERPOLATED_REGEX = re.compile(r"%%([^%]+?)%%")

    # Grouping pattern: e.g. {test.exe,foo.doc,bar.txt}
    GROUPING_PATTERN = re.compile("({([^}]+,[^}]+)}|%%([^%]+?)%%)")
    RECURSION_REGEX = re.compile(r"\*\*(\d*)")

    # A regex indicating if there are shell globs in this path.
    GLOB_MAGIC_CHECK = re.compile("[*?[]")

    def __init__(self, *args, **kwargs):
        super(IRGlob, self).__init__(*args, **kwargs)
        self.component_cache = utils.FastStore(50)

        # Default path seperator is platform dependent.
        if not self.plugin_args.path_sep:
            self.plugin_args.path_sep = (
                "\\" if platform.system() == "Windows" else "/")

        # By default use the root of the filesystem.
        if self.plugin_args.root is None:
            self.plugin_args.root = self.plugin_args.path_sep

    def _interpolate_grouping(self, pattern):
        # Take the pattern and split it into components around grouping
        # patterns. Expand each grouping pattern to a set.

        # e.g.  /foo{a,b}/bar -> ["/foo", set(["a", "b"]), "/bar"]
        result = []
        components = []
        offset = 0
        for match in self.GROUPING_PATTERN.finditer(pattern):
            match_str = match.group(0)
            # Alternatives.
            if match_str.startswith("{"):
                components.append([pattern[offset:match.start()]])

                # Expand the attribute into the set of possibilities:
                alternatives = match.group(2).split(",")
                components.append(set(alternatives))
                offset = match.end()

            # KnowledgeBase interpolation.
            elif match_str.startswith("%"):
                components.append([pattern[offset:match.start()]])

                kb = self.session.GetParameter("knowledge_base")
                alternatives = kb.expand(match_str)

                components.append(set(alternatives))
                offset = match.end()

            else:
                raise plugin.PluginError(
                    "Unknown interpolation %s" % match.group(0))

        components.append([pattern[offset:]])
        # Now calculate the cartesian products of all these sets to form all
        # strings.
        for vector in itertools.product(*components):
            result.append(u"".join(vector))

        # These should be all possible patterns.
        # e.g. /fooa/bar , /foob/bar
        return result

    def convert_glob_into_path_components(self, pattern):
        """Converts a glob pattern into a list of pathspec components.

        Wildcards are also converted to regular expressions. The pathspec
        components do not span directories, and are marked as a regex or a
        literal component.

        We also support recursion into directories using the ** notation.  For
        example, /home/**2/foo.txt will find all files named foo.txt recursed 2
        directories deep. If the directory depth is omitted, it defaults to 3.

        Example:
         /home/test**/*exe -> [{path: 'home', type: "LITERAL",
                               {path: 'test.*\\Z(?ms)', type: "RECURSIVE",
                               {path: '.*exe\\Z(?ms)', type="REGEX"}]]

        Args:
          pattern: A glob expression with wildcards.

        Returns:
          A list of PathSpec instances for each component.

        Raises:
          ValueError: If the glob is invalid.

        """
        pattern_components = common.FileSpec(
            pattern, path_sep=self.plugin_args.path_sep).components()

        components = []
        for path_component in pattern_components:
            if not path_component:
                continue

            # A ** in the path component means recurse into directories that
            # match the pattern.
            m = self.RECURSION_REGEX.search(path_component)
            if m:
                depth = 3

                # Allow the user to override the recursion depth.
                if m.group(1):
                    depth = int(m.group(1))

                path_component = path_component.replace(m.group(0), "*")
                component = RecursiveComponent(
                    session=self.session,
                    component=fnmatch.translate(path_component),
                    cache=self.component_cache,
                    depth=depth)

            elif self.GLOB_MAGIC_CHECK.search(path_component):
                component = RegexComponent(
                    session=self.session,
                    cache=self.component_cache,
                    component=fnmatch.translate(path_component))

            else:
                component = LiteralComponent(
                    session=self.session,
                    cache=self.component_cache,
                    component=path_component)

            components.append(component)

        return components

    def _filter(self, node, path):
        """Path is the pathspec of the path we begin evaluation with."""
        for component, child_node in node.iteritems():
            # Terminal node - yield the result.
            if not child_node:
                for subpath in component.filter(path):
                    yield subpath

            else:
                # Non - terminal node, walk the subnode recursively.
                for matching_path in component.filter(path):
                    for subpath in self._filter(child_node, matching_path):
                        yield subpath

    def make_component_tree(self, globs):
        expanded_globs = []
        for glob in globs:
            expanded_globs.extend(self._interpolate_grouping(glob))

        component_tree = {}
        for glob in expanded_globs:
            node = component_tree
            for component in self.convert_glob_into_path_components(glob):
                node = node.setdefault(component, {})

        return component_tree

    def collect_globs(self, globs):
        component_tree = self.make_component_tree(globs)
        root = common.FileSpec(self.plugin_args.root,
                               path_sep=self.plugin_args.path_sep)
        for path in self._filter(component_tree, root):
            yield common.FileFactory(path, session=self.session)

    def collect(self):
        for x in self.collect_globs(self.plugin_args.globs):
            yield dict(path=x)


def print_component_tree(tree, depth=""):
    """This is used for debugging the component_tree."""
    if not tree:
        return

    for k, v in tree.iteritems():
        print "%s %s:" % (depth, k)
        print_component_tree(v, depth + " ")



class IRDump(IRGlob):
    """Hexdump files from disk."""

    name = "hexdump_file"

    __args = [
        dict(name="start", type="IntParser", default=0,
             help="An offset to hexdump."),

        dict(name="length", type="IntParser", default=100,
             help="Maximum length to dump."),

        dict(name="width", type="IntParser", default=24,
             help="Number of bytes per row"),

        dict(name="rows", type="IntParser", default=4,
             help="Number of bytes per row"),
    ]

    table_header = [
        dict(name="divider", type="Divider"),
        dict(name="FileSpec", hidden=True),
        dict(name="offset", style="address"),
        dict(name="hexdump", width=65),
    ]

    def collect(self):
        for hit in super(IRDump, self).collect():
            path = hit.get("path")
            if path:
                fd = path.open()
                if fd:
                    yield dict(divider=path.filename)

                    to_read = min(
                        self.plugin_args.length,
                        self.plugin_args.width * self.plugin_args.rows)
                    for offset in utils.xrange(
                            self.plugin_args.start,
                            self.plugin_args.start + to_read,
                            self.plugin_args.width):

                        fd.seek(offset)
                        data = fd.read(self.plugin_args.width)
                        if not data:
                            break

                        yield dict(
                            offset=offset,
                            FileSpec=path.filename,
                            hexdump=utils.HexDumpedString(data),
                            nowrap=True,
                            hex_width=self.plugin_args.width)
