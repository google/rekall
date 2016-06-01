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
import re
import os

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
    def __init__(self, component):
        self.component = component

    def __eq__(self, other):
        return unicode(self) == unicode(other)

    def __hash__(self):
        return hash(unicode(self))

    def __str__(self):
        return "%s:%s" % (self.__class__.__name__, self.component)


class LiteralComponent(Component):

    def filter(self, file_info):
        for child in file_info.list():
            basename = os.path.basename(child.filename.name).lower()
            if basename == self.component.lower():
                yield child
                return


class RegexComponent(Component):
    def __init__(self, *args):
        super(RegexComponent, self).__init__(*args)
        self.component_re = re.compile(self.component, re.I)

    def filter(self, file_info):
        for child in file_info.list():
            basename = os.path.basename(child.filename.name).lower()
            if self.component_re.match(basename):
                yield child


class RecursiveComponent(RegexComponent):
    def __init__(self, component, depth):
        super(RecursiveComponent, self).__init__(component)
        self.depth = depth

    def filter(self, file_info, depth=0):
        if depth == self.depth:
            return

        for child in file_info.list():
            yield child

            basename = os.path.basename(child.filename.name).lower()
            if self.component_re.match(basename):
                for subitem in self.filter(child, depth+1):
                    yield subitem


class IRGlob(common.AbstractIRCommandPlugin):
    """Search for files by filename glob.

    This code roughly based on the Glob flow in GRR.
    """

    name = "glob"

    __args = [
        dict(name="globs", positional=True, type="ArrayString",
             help="List of globs to return."),
        dict(name="root", default="/",
             help="Root directory to glob from."),
        dict(name="case_insensitive", default=True, type="Bool",
             help="Globs will be case insensitive."),

    ]

    table_header = [
        dict(name="Path", type="FileInformation"),
    ]

    INTERPOLATED_REGEX = re.compile(r"%%([^%]+?)%%")

    # Grouping pattern: e.g. {test.exe,foo.doc,bar.txt}
    GROUPING_PATTERN = re.compile("{([^}]+,[^}]+)}")
    RECURSION_REGEX = re.compile(r"\*\*(\d*)")

    # A regex indicating if there are shell globs in this path.
    GLOB_MAGIC_CHECK = re.compile("[*?[]")

    def _interpolate_grouping(self, pattern):
        # Take the pattern and split it into components around grouping
        # patterns. Expand each grouping pattern to a set.

        # e.g.  /foo{a,b}/bar -> ["/foo", set(["a", "b"]), "/bar"]
        result = []
        components = []
        offset = 0
        for match in self.GROUPING_PATTERN.finditer(pattern):
            components.append([pattern[offset:match.start()]])

            # Expand the attribute into the set of possibilities:
            alternatives = match.group(1).split(",")
            components.append(set(alternatives))
            offset = match.end()

        components.append([pattern[offset:]])
        # Now calculate the cartesian products of all these sets to form all
        # strings.
        for vector in itertools.product(*components):
            result.append(u"".join(vector))

        # These should be all possible patterns.
        # e.g. /fooa/bar , /foob/bar
        return result

    def interpolate(self, glob):
        """Interpolate the glob.

        Returns a list of globs with only wild cards.
        """
        return self._interpolate_grouping(glob)

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
        components = []
        for path_component in pattern.split("/"):
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
                    fnmatch.translate(path_component), depth=depth)

            elif self.GLOB_MAGIC_CHECK.search(path_component):
                component = RegexComponent(fnmatch.translate(path_component))

            else:
                component = LiteralComponent(path_component)

            components.append(component)

        return components

    def _filter(self, node, file_information):
        for component, child_node in node.iteritems():
            # Terminal node - yield the result.
            if not child_node:
                for item in component.filter(file_information):
                    yield item

            else:
                # Non - terminal node, walk the subnode recursively.
                for matching_file_info in component.filter(file_information):
                    for item in self._filter(child_node, matching_file_info):
                        yield item

    def collect_globs(self, globs):
        expanded_globs = []
        for glob in globs:
            expanded_globs.extend(self.interpolate(glob))

        component_tree = {}
        for glob in expanded_globs:
            node = component_tree
            for component in self.convert_glob_into_path_components(glob):
                node = node.setdefault(component, {})

        root = common.FileFactory(self.plugin_args.root, session=self.session)
        for item in self._filter(component_tree, root):
            yield item

    def collect(self):
        for x in self.collect_globs(self.plugin_args.globs):
            yield (x, )
