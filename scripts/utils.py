import subprocess
import logging
import re
import markdown
import yaml

import os

SEPERATOR = "\n---\n"
MARKDOWN_EXTENSIONS = [".md", ".markdown"]
MD_EXTENSIONS = [
    'fenced_code',
    'codehilite(css_class=highlight)',
    'smarty',
    'tables',
    'sane_lists',
    'wikilinks(end_url=.html)',
    ]

ASCIIDOC_EXTENSIONS = [".txt", ".adoc"]
ASCIIDOC_CMD = ("asciidoc -a icons -a linkcss "
                "-a stylesdir=/css -a data-uri "
                "".split())

VALID_EXTENSIONS = ASCIIDOC_EXTENSIONS + MARKDOWN_EXTENSIONS
EXCLUDED_DIRECTORIES = ["img", "blogg_posts"]


class Page(dict):
    def __getattr__(self, attr):
        return self.get(attr, None)

    def __setattr__(self, attr, value):
        if hasattr(self.__class__, attr) or attr in self.__dict__:
            super(Page, self).__setattr__(attr, value)
        else:
            self[attr] = value

    def CheckContentCache(self):
        cache_path = os.path.abspath("./_cache/%s" % self.filename.replace(
            "/", "_"))

        try:
            # Only return the cache it is it newer than the original file.
            if os.stat(cache_path).st_mtime > os.stat(self.filename).st_mtime:
                return open(cache_path).read().decode("utf8", "ignore")
        except (OSError, IOError):
            pass

        # Recalculate the cache.
        content = self._parse_content()
        with open(cache_path, "wb") as fd:
            fd.write(content.encode("utf8"))

        return content

    def _parse_content(self):
        content = self.raw_content

        if self.extension in MARKDOWN_EXTENSIONS:
            return ConvertFromMD(content)

        elif self.extension in ASCIIDOC_EXTENSIONS:
            return ConvertFromAsciiDoc(content)

        else:
            return content

    @property
    def content(self):
        if self.parsed_content is not None:
            return self.parsed_content

        self.parsed_content = self.CheckContentCache()

        return self.parsed_content

    @content.setter
    def content(self, value):
        self.parsed_content = value


def GetInclude(filename):
    return open(filename).read()

def ConvertFromMD(text):
    """Convert the data from markdown to html."""
    return markdown.markdown(text, extensions=MD_EXTENSIONS)


def ConvertFromAsciiDoc(text):
    cmd = ASCIIDOC_CMD[:] + [
        "-a", "iconsdir=%s/img/icons" % os.getcwd(),
        "-a", "imagesdir=%s" % os.getcwd(),
        "-"]
    print cmd
    pipe = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE)

    stdoutdata, _ = pipe.communicate(text.encode("utf8"))

    m = re.search("<body[^>]*>(.+)</body", stdoutdata, re.S|re.M)

    return m.group(1).decode("utf8", "ignore")


def GetUrlFromFilename(filename):
    return os.path.abspath(filename)[len(os.getcwd()):]


def ParsePage(filename):
    """Read a page and return its metadata blob."""
    filename = os.path.abspath(filename)
    base_name, extension = os.path.splitext(filename)
    if extension not in VALID_EXTENSIONS:
        return None

    try:
        text = open(filename).read().decode("utf8", "ignore").lstrip()
    except (OSError, IOError):
        return None

    match = re.match("^---\n(.*?)---\n(.*)", text, re.S | re.M)
    if not match:
        return None

    try:
        metadata = Page(yaml.safe_load(match.group(1)) or {})
    except ValueError:
        logging.warning("Invalid page %s" % filename)
        return None

    metadata.extension = extension
    metadata.raw_content = match.group(2)
    metadata.filename = filename
    metadata.base_name = base_name
    metadata.url = GetUrlFromFilename(base_name) + ".html"
    metadata.type = "file"

    return metadata


def ListPages(path):
    """A generator for page metadata from path."""
    # The path can be provided as an absolute, or relative to the document root.
    if not path.startswith(os.getcwd()):
        path = os.path.abspath("%s/%s" % (os.getcwd(), path))

    for filename in os.listdir(path):
        full_path = os.path.abspath("%s/%s" % (path, filename))

        if os.path.isdir(full_path):
            yield Page(filename=full_path, type="directory",
                       url=GetUrlFromFilename(filename))

        else:
            page = ParsePage(full_path)
            if page is not None:
                yield page
