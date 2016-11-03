# Rekall Forensic and Incident Response Agent.

Please do not use yet - this code is highly experimental and subject
to rapid changes. This release is for evaluation only - we welcome
feedback.

## Overview

The Rekall Agent is an endpoint response agent based on the Rekall
Framework. The main motivations for the Rekall Agest are

- Very simple architecture - everything is a file. We just move files
  around.

- Very easy to deploy. Cloud based deployment ensures very high level
  of scalability and low cost.


## Quick start

The system architecture is discussed in length in the following
documents:

 * http://rekall-forensic.blogspot.ch/2016/10/the-rekall-agent-whitepaper.html

In this short document I will discuss how to get up and running
quickly.

# Installation

The Rekall Agent is an additional python package that depends on
Rekall. Therefore installation of the Rekall Agent follows the same
pattern as installing Rekall itself. To install the released version,
simply create a new virtual environment, switch to it and "pip install
rekall-agent":

```
$ virtualenv  /tmp/MyEnv
New python executable in /tmp/MyEnv/bin/python
Installing setuptools, pip...done.
$ source /tmp/MyEnv/bin/activate
$ pip install --upgrade setuptools pip wheel
$ pip install rekall-agent
```

# Local HTTP based deployment.

In this part we will run the Rekall Agent with our own hosted HTTP
server. This setup is suitable for those users who do not want to use
the Google Cloud - but they will need to ensure the servers are
publically accessible and have sufficient disk space to store all the
collected data. Nevertheless this mode of operation is a good way to
try out the Rekall Agent on a small scale installation.

To create the installation we need to create a set of configuration
files. These are created inside a directory:

```
(Dev) $ rekall agent_server_initialize_http /tmp/new_HTTP/ \
      --base_url http://127.0.0.1:8000/ --bind_port 8000 \
      --client_writeback_path ~/.rekall_agent
Message
-------
Generating new CA private key into /tmp/new_HTTP/ca.private_key.pem and \
	   /tmp/new_HTTP/ca.cert.pem
Generating new Server private keys into /tmp/new_HTTP/server.private_key.pem \
	   and /tmp/new_HTTP/server.certificate.pem
Writing server config file /tmp/new_HTTP/server.config.yaml
Writing client config file /tmp/new_HTTP/client.config.yaml
Done!
```

In the above the main configuration file is writen to
`/tmp/new_HTTP/server.config.yaml`. This file contains keys required
to manage the installation and so should be protected.

The `--base_url` refers to the publicaly accessible URL of the
server. The `--bind_port` is the port at which the http server should
listen. The `--client_writeback_path` is a path where the client may
store its state file (including its own keys).

Next we run an instance of the http server, worker and controller:

```
rekall -v --agent_config /tmp/new_HTTP/server.config.yaml http_server
rekall -v --agent_config /tmp/new_HTTP/server.config.yaml worker --loop 5
rekall -v --agent_config /tmp/new_HTTP/server.config.yaml agent_controller
```

The agent client has no credentials and therefore uses its own
specific configuration file. We can start it:

```
rekall -v --agent_config /tmp/new_HTTP/client.config.yaml agent
```

# Cloud based deployment.

For very large scale deployments it is better to use the cloud. In
this case users do not need to run any servers themselves.

In order to deploy to the cloud you will need two things:

1. A Google Cloud Project service account keys - this gives access to
   cloud storage.
2. A new Google Cloud Storage bucket to hold all the data.

First create a new cloud project through the Google Cloud Console
(https://console.cloud.google.com).

Next create a service account:
 - Select IAM & Admin from the drop down.
 - Select Service Accounts from the side box.
 - Click "Create Service Account".
 - Give a name to the account and select role "Storage Admin".
 - Select "Furnish a new private key" and select JSON as the format.
 - When the account is created the service account JSON file is
   downloaded to your browser. Move it someplace safe.

Next Create a new Bucket:
 - Select "Storage" from the side menu.
 - Click "Create Bucket" to create a new bucket. Give it a name.

Now we can create the relevant config files for the Rekall Agent:
```
 $ rekall agent_server_initialize_gcs /tmp/new_GCS/ --bucket rekall-test \
   --service_account_path ~/.rekall_test_manager \
   --client_writeback_path ~/.rekall-agent
Message
-------
Reusing existing CA keys in /tmp/new_GCS/ca.cert.pem
Reusing existing server keys in /tmp/new_GCS/server.certificate.pem
Server config at /tmp/new_GCS/server.config.yaml exists. Remove to regenerate.
Writing client config file /tmp/new_GCS/client.config.yaml
Writing manifest file.
Writing manifest file to rekall-test/manifest
```

Here we provide the path to the downloaded JSON file as
`--service_account_path` and the bucket name as `--bucket`.

We can start all the services as before:
```
rekall -v --agent_config /tmp/new_GCS/server.config.yaml worker --loop 5
rekall -v --agent_config /tmp/new_GCS/server.config.yaml agent_controller
```

And deploy the clients with their config files:
```
rekall -v --agent_config /tmp/new_GCS/client.config.yaml agent
```
