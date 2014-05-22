"""Convert all the asciidocs to HTML."""

import os
import subprocess
import StringIO

ASCIIDOC_EXTENSION = ".adoc"
ASCIIDOC_CMD = ("asciidoc -a icons -a linkcss "
                "-a stylesdir=/css -a data-uri "
                "-b rekall".split())

for root, dirs, files in os.walk("."):
    for name in files:
        path = os.path.join(root, name)
        if path.endswith(ASCIIDOC_EXTENSION):
            output_path = path.replace(ASCIIDOC_EXTENSION, ".html")
            print path, output_path
            data = open(path).read()

            front_matter, content = data.split("\n---\n", 1)

            cmd = ASCIIDOC_CMD[:] + [
                "-a", "iconsdir=%s/img/icons" % os.getcwd(),
                "-a", "imagesdir=%s" % os.getcwd(),
                "-"]
            print cmd
            pipe = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE)
            stdoutdata, _ = pipe.communicate(content)

            with open(output_path, "wb") as fd:
                fd.write(front_matter)
                fd.write("\n---\n")
                fd.write(stdoutdata)


