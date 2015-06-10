#!/usr/bin/python
"""This is a CGI handler for github push webhooks.

To install:

1. Copy this file to your server cgi-bin directory (e.g. /usr/lib/cgi-bin/).\
2. Modify the SECRET below.
3. create a new github web hook with the URL to this cgi file and update the
   SECRET.

All this file does is write a control file in the specified location when github
sends a push notification.
"""
import json
import hashlib
import hmac
import os
import sys

# Modify these for your installation.
SECRET = "iamasecret"
CONTROL = "/home/rekalltest/control"


data = sys.stdin.read()

print("""Content-type: text/html

<html><h1>
""")

# Verify the hmac.
hmac_sig = hmac.HMAC(SECRET, data, hashlib.sha1).hexdigest()
if hmac_sig != os.environ['HTTP_X_HUB_SIGNATURE'].split("=")[1]:
    print("Denied")
else:
    # Create the control file to kick off the test run.
    print("Scheduling run.")
    data = json.loads(data)
    data["action"] = "start"

    with open(CONTROL, "wb") as fd:
        fd.write(json.dumps(data))
