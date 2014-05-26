#!/usr/bin/python2

"""
Generate the site.
"""
import pdb
import os
import utils
import layout

def RenderPage(filename):
    metadata = utils.ParsePage(filename)
    if metadata is None:
        print "%s not valid template" % filename
        return

    renderer = getattr(layout, metadata.get("layout", "default"))
    result = renderer(metadata)

    with open("%s.html" % metadata["base_name"], "wb") as fd:
        fd.write(result.encode("utf8"))


def main(path="."):
    for root, dirs, files in os.walk(path, topdown=True):
        # Prune dirs with _
        excluded = utils.EXCLUDED_DIRECTORIES
        dirs[:] = [x for x in dirs
                   if not x.startswith("_") and x not in excluded]

        for name in files:
            path = os.path.join(root, name)
            extension = os.path.splitext(name)[1]
            if extension in utils.VALID_EXTENSIONS:
                print "Converting %s" % path
                RenderPage(path)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pdb.post_mortem()
