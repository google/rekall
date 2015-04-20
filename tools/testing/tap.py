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
import sys
import time
import yaml
import smtplib
from email.mime import text

PARSER = argparse.ArgumentParser()
PARSER.add_argument("-c", "--config", required=True,
                    help="The config file to parse.")


def RunTests(configuation, timestamp):
    result = 0
    test_prog = configuation["TAP"]["testsuite"]
    configs = configuation["TAP"]["test_directories"]
    control = configuation["control"]
    for path in configs:
        args = [test_prog, "-c", os.path.join(path, "tests.config"),
                "--output_dir", timestamp, "--control", control]
        print "Running test %s" % " ".join(args)
        res = subprocess.call(args)
        print "Test returned status ", res

    if res != 0:
        result = res

    return result


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


    out = """
<html>
<head>
<!-- Latest compiled and minified CSS -->
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.4/css/bootstrap.min.css">

<!-- Optional theme -->
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.4/css/bootstrap-theme.min.css">

<!-- Latest compiled and minified JavaScript -->
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.4/js/bootstrap.min.js"></script>

</head>
<body><h1>TAP run @ %s</h1>
<table class="table">
   <tr><th>Test</th>
""" % (timestamp)

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
                css_class = ("btn btn-success btn-sm"
                             if test_result else "btn btn-danger btn-sm")
                text_value = "PASS" if test_result else "FAIL"
                suffix = "" if test_result else ".diff"

                # Add an entry for each test in this suite.
                out += """
<td>
  <a href='../%s/%s/%s%s'>
    <button class='%s'>%s</button>
  </a>
</td>""" % (name, timestamp, test, suffix, css_class, text_value)

        out += "</tr>\n"
    out += "</table></body></html>"

    return out


def SendEmail(configuation, passed=True):
    """Send an email with the status of the test run."""
    with open(configuation["control"]) as fd:
        data = json.load(fd)
        data.update(configuation["ProjectInfo"])
        data.update(configuation["Email"])
        duration = time.time() - configuation["start_time"]
        data["duration"] = "%d minutes and %d seconds" % divmod(duration, 60)
        data["short_hash"] = data["head_commit"]["id"][:7]

    if passed:
        data["icon"] = "success.png"
        data["color_style"] = "background-color:#baecb7;color:#32a32d;"
        data["message"] = "Build %s passed" % data["short_hash"]
    else:
        data["icon"] = "failed.png"
        data["color_style"] = "background-color:#fdcdce;color:#df192a;"
        data["message"] = "Build failed"

    TEMPLATE = """
    <div>
      <table style="padding:0px;border:0px;width:100%;color:#606060;font-size:20px;margin-bottom:15px;margin-top:15px">
        <tbody>
          <tr style="padding:0px;border:0px">
            <td style="padding:0px;border:0px;vertical-align:middle">
              <img src="{logo_url}" height="25">
              <span style="vertical-align:middle;margin-left:3px">
                <strong><a href="{project_url}" style="text-decoration:underline;color:#606060" target="_blank">{project_name}</a></strong>
              </span>
            </td>
          </tr>
        </tbody>
      </table>
      <div style="border-radius:5px;padding:0px;width:570px;font-size:13px">
        <div>
         <table style="padding:0px;border:0px;width:100%;border-spacing:0">
           <thead>
             <tr style="padding:0px;border:0px;font-weight:700;font-size:18px;{color_style}">
               <td style="border:0px;border-top:1px solid #808080;border-bottom:1px solid #adadad;width:50px;padding:0px;text-align:center;vertical-align:middle;padding-top:5px;border-left:1px solid #606060;border-top-left-radius:5px">
                 <div style="width:25px;min-height:30px;margin-left:15px;margin-top:0px;vertical-align:middle">
                   <img height="25" src="{root_url}/images/{icon}" width="25">
                 </div>
               </td>
               <td style="border:0px;padding:0px 20px 0px 0px;vertical-align:middle;border-top:1px solid #808080;border-bottom:1px solid #adadad">
                 <span style="display:inline-block;margin-top:12px;vertical-align:middle">
                   <a href="{dashboard_url}" style="font-weight:bold;text-decoration:underline;{color_style}" target="_blank">
                     {message}
                   </a>
                 </span>
               </td>
               <td align="right" style="border:0px;font-weight:normal;font-size:12px;padding:0px 20px 0px 0px;vertical-align:middle;border-top:1px solid #808080;border-bottom:1px solid #adadad;border-right:1px solid #606060;border-top-right-radius:5px">
                  <div style="vertical-align:middle;padding:0px;display:inline-block;width:20px;min-height:20px">
                     <img height="20" src="{root_url}/images/stopwatch-silhouette-hi.png" width="20">
                  </div>
                 <span style="vertical-align:middle">{duration}</span></td>
             </tr>
          </thead>
          <tbody style="margin-bottom:40px">
          <tr style="padding:0px;border:0px">
              <td style="border:0px;height:20px;width:50px;padding:0px;border-left:1px solid #adadad;padding-top:20px;padding-bottom:5px;text-align:center"></td>
              <td style="border:0px;color:#808080;padding:10px 20px 10px 0px;height:20px;padding-top:20px;padding-bottom:5px;">
               <strong>{head_commit[author][name]}</strong>
              </td>
              <td style="border:0px;color:#808080;padding:10px 20px 10px 0px;height:20px;padding-top:20px;padding-bottom:5px; border-right:1px solid #adadad;">
                <a href="{head_commit[url]}">Commit {short_hash}</a>
              </td>
          </tr>
          <tr style="padding:0px;border:0px">
            <td style="border:0px;height:20px;width:50px;padding:0px;border-left:1px solid #adadad;border-bottom-left-radius:5px;border-bottom:1px solid #adadad">&nbsp;</td>
            <td colspan="2" style="border:0px;color:#808080;padding:10px 20px 10px 0px;height:20px;border-right:1px solid #adadad;padding-bottom:20px;padding-top:0px;border-bottom:1px solid #adadad;border-bottom-right-radius:5px">
              {head_commit[message]}
            </td>
       </tr>
      </tbody>
    </table>
    </div>
    </div>
    """
    message = text.MIMEText(TEMPLATE.format(**data), "html")
    message["Subject"] = data["message"]
    message["From"] = "noreply@tap.rekall-forensic.com"
    message["To"] = data["destination_email"]

    session = smtplib.SMTP(configuation["Email"]["smtp_server"],
                           configuation["Email"]["smtp_server_port"])
    session.ehlo()
    session.starttls()
    session.login(configuation["Authentication"]["gmail_account"],
                  configuation["Authentication"]["gmail_smtp_password"])
    session.sendmail(message["From"], [message["To"]], message.as_string())
    session.quit()


def main():
    args = PARSER.parse_args()

    timestamp = time.strftime("%Y%m%d%H%M")
    configuation = yaml.safe_load(open(args.config))
    configuation["start_time"] = time.time()

    result = RunTests(configuation, timestamp)

    html_page = RenderResult(configuation["TAP"]["test_directories"], timestamp)
    output_path = configuation["TAP"]["output_directory"]

    with open(os.path.join(output_path, timestamp + ".html"), "wb") as fd:
        fd.write(html_page)

    with open(os.path.join(output_path, "latest.html"), "wb") as fd:
        fd.write(html_page)

    # Now send the email
    SendEmail(configuation, result == 0)

    sys.exit(result)


if __name__ == "__main__":
    main()
