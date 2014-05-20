#!/bin/python
# Quick directory index creator for cheap maven repositories by Darien Hager
# Inspired by the bash script from http://chkal.blogspot.com/2010/09/maven-repositories-on-github.html

from string import Template
from time import strftime
import os, sys

# The magic token is used to guard against accidents. This script will not overwrite files that do not contain it.
# The token must not be split over two lines.
INDEX_FNAME = "index.html"
MAGIC_TOKEN = "711CD4AFDDF4F6E6E1A9986267B5FEC62DD273FE8A63E236D3351E3E846CCDE2"

SELF_PATH = os.path.abspath(sys.argv[0])

# Taken from http://stackoverflow.com/questions/1094841/reusable-library-to-get-human-readable-version-of-file-size
def formatSize(bytes):
    for x in ['b','k','m','g','t']:
        if bytes < 1024.0:
            if x != 'b':
                return "%3.1f%s" % (bytes, x)
            else:
                return "%3.0f%s" % (bytes, x)
        bytes /= 1024.0

def buildListing(dirs,files,label):

    pageTemplate = Template("""<html>
        <head>
            <title>Directory Listing</title>
            <!-- Anti-overwrite token $tok -->
        </head>
        <body>
            <table>
                <tr>
                    <th><!--Icon--></th>
                    <th>Name</th>
                    <th>Size</th>
                </tr>
                <tr>
                    <td>[DIR]</td>
                    <td><a href="..">..</a></td>
                    <td></td>
                </tr>
                $rowdata
            </table>
        </body>

    </html>
    """)

    rowTemplate = Template("""
                <tr>
                    <td>$icon</td>
                    <td><a href="$link">$name</a></td>
                    <td>$size</td>
                </tr>
    """)

    rowFragment = ""
    for d in dirs:
        bname = os.path.basename(d)
        rowFragment += rowTemplate.substitute(
            icon="[DIR]",
            name=bname + "/",
            link="./"+bname+"/index.html",
            size=""
        )
    for f in files:
        bname = os.path.basename(f)
        rowFragment += rowTemplate.substitute(
            icon="[FILE]",
            name=bname,
            link="./"+bname,
            size=formatSize(os.path.getsize(f))
        )


    html = pageTemplate.substitute(
        tok=MAGIC_TOKEN,
        label=label,
        time=strftime("%Y-%m-%d %H:%M:%S"),
        rowdata=rowFragment
        )

    return html


def listdir(d):
    items = os.listdir(d)
    dirs = []
    files = []
    items.sort()
    for i in items:
        if i.startswith("."): continue # Ignore current/parent/hidden dirs
        if i == "index.html" : continue # Ignore indexes
        path = os.path.join(d,i)
        if os.path.abspath(path) == SELF_PATH: continue # Don't index self
        if os.path.isdir(path):
            dirs.append(path)
        elif os.path.isfile(path):
            files.append(path)

    return (dirs,files)


if __name__ == "__main__":

    rootPath = os.getcwd()
    if(len(sys.argv)>=2):
        rootPath = sys.argv[1]
        if not os.path.isdir(rootPath):
            print "Invalid path given: "+rootPath
            exit(1)

    toVisit = [rootPath]
    dryRun = True;

    while(len(toVisit) > 0):
        current = toVisit.pop()

        label = None
        try:
            label = os.path.relpath(current,rootPath)
        except AttributeError:
            label = os.path.basename(os.path.abspath(current))

        (directories,files) = listdir(current)
        html = buildListing(directories,files,label)
        target = os.path.join(current,"index.html")
        toVisit.extend(directories)


        doWrite = True;
        if os.path.isfile(target):
            # Check anti-accident protection
            doWrite = False;
            fh = open(target,"r")
            for line in fh:
                if line.find(MAGIC_TOKEN) >=0 :
                    doWrite = True;
                    break;
            fh.close()

        if(doWrite):
            print target
            fh = open(target,"w")
            fh.write(html)
            fh.close()
        else:
            print "Cautiously refusing to overwrite "+target


