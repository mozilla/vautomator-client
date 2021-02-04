# vautomator-client
Client to use the vautomator-serverless back-end.

## Install

1. Clone this repository: `git clone https://github.com/mozilla/vautomator-client.git && cd vautomator-client`
2. Create a virtual env (I use `pipenv`): `pipenv --python 3.x`
3. Install as egg: `python setup.py install`

## Usage

_**NOTE:** This client is only intended to work with the vautomator API (see https://github.com/mozilla/vautomator-serverless)_

The client supports 3 modes: `run` to run a vulnerability scan, `download` to download scan results (manually, if you have to), and `monitor` to monitor CT logs for new subdomains under "mozilla.com", "mozilla.org" and "firefox.com".

It is highly recommended to use the great `maws` tool (https://pypi.org/project/mozilla-aws-cli-mozilla/), before running a scan with this client. Otherwise, the client will prompt for an API key, which you will have to obtain from `infosec-dev` AWS account.

### Pre-requisites

- In your virtual environment, install `maws`: `pip install mozilla-aws-cli-mozilla`
- Sign in to AWS via SSO: `eval $(maws -w)`. When prompted in the browser, select `infosec-dev-MAWS-Admin` role. If everything goes well you now should have AWS credentials set as your environment variables.

### Run it!
1. To run a scan on a target host: `va_ondemand run www.mozilla.org`
    - If everything goes well, you should, in an hour or so, have results sent to an [SNS Topic](https://github.com/mozilla/vautomator-serverless/blob/31908da57a769dd097ee73977a7863d3af3143ca/serverless.yml#L419-L432) which in turn has a Google Group, [vautomator-results](https://groups.google.com/a/mozilla.com/forum/#!forum/vautomator-results) subscribed to it. If you join this Google Group, you will get results emailed to you.
2. To (manually) download results for a scan: `va_ondemand download www.mozilla.org`.
    - This should create a `tar.gz` file under a folder called `results` in the current working directory, containing output from tooling.
3. To monitor CT logs and automatically kick off a scan for specific subdomains: `va_ondemand monitor`.
    - Note that this mode is blocking, as it will listen for events in certificate transparency logs, until you end the program.
