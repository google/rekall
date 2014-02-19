#!/usr/bin/env python

# Rekall
# Copyright 2014 Google Inc. All Rights Reserved.
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
import argparse
import collections
import json
import os
import subprocess
import time
import yaml

PARSER = argparse.ArgumentParser()
PARSER.add_argument("-c", "--config", required=True,
                    help="The config file to parse.")


def RunTests(test_prog, configs, timestamp):
  for path in configs:
    print "Running test %s" % path
    subprocess.call([test_prog, "-c", os.path.join(path, "tests.config"),
                     "--output_dir", timestamp])


def RenderResult(configs, timestamp):
  results = collections.OrderedDict()
  all_tests = set()
  for config in configs:
    name = os.path.basename(config)
    out_path = os.path.join(config, timestamp)

    results[name] = {}
    result = json.load(open(os.path.join(out_path, "results")))
    for success in result["passes"]:
      all_tests.add(success)
      results[name][success] = True

    for fail in result["fails"]:
      all_tests.add(fail)
      results[name][fail] = False


  out = "<html><body><h1>TAP run @ %s</h1><table><tr><th>Test</th>" % (
      timestamp)

  for name in results:
    out += "<th>%s</th>" % name

  out += "</tr>"

  for test in sorted(all_tests):
    out += "<tr><td>%s</td>" % test
    for name in results:
      test_result = results[name].get(test)
      if test_result is None:
        out += "<td></td>"
      else:
        color = "green" if test_result else "red"
        text = "PASS" if test_result else "FAIL"
        suffix = "" if test_result else ".diff"

        out += "<td bgcolor=%s><a href='../%s/%s/%s%s'>%s</a></td>" % (
            color, name, timestamp, test, suffix, text)

    out += "</tr>\n"
  out += "</table></body></html>"

  return out


def main():
  args = PARSER.parse_args()

  timestamp = time.strftime("%Y%m%d%H%M")
  configuation = yaml.safe_load(open(args.config))


  RunTests(configuation["testsuite"],
           configuation["test_directories"], timestamp)

  html_page = RenderResult(configuation["test_directories"], timestamp)
  output_path = configuation["output_directory"]

  with open(os.path.join(output_path, timestamp + ".html"), "wb") as fd:
    fd.write(html_page)

  with open(os.path.join(output_path, "latest.html"), "wb") as fd:
    fd.write(html_page)


if __name__ == "__main__":
  main()
