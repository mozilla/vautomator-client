import logging
import requests
import json
import time
import os
import sys
import boto3
import argparse
import getpass
import shutil
import tarfile
import certstream
import yaml
from va_ondemand.target import Target

logging.basicConfig(stream=sys.stdout, level=logging.INFO)


def load_config():

    config = {}
    path = os.path.join(os.path.dirname(__file__), '..', 'config.yml')
    try:
        with open(path) as fd:
            config = yaml.safe_load(fd)
    except Exception as e:
        logger.error("Could not parse configuration file: {}".format(e))
        sys.exit(127)
    return config


def validate_target(fqdn):
    try:
        Target(fqdn)
    except AssertionError:
        logging.error("Target validation failed: target must be an FQDN or IPv4 only.")
        return False
    return True


def check_authorization(aws_profile=None, aws_region=region):
    if aws_profile:
        # Establish a session with that profile if given
        session = boto3.Session(profile_name=aws_profile, region_name=aws_region)
        # Programmatically obtain the REST API key
        apigw_client = session.client("apigateway")
        aws_response = apigw_client.get_api_keys(nameQuery="vautomator-serverless", includeValues=True)["items"][0]
        rest_api_id, stage_name = "".join(aws_response["stageKeys"]).split("/")
        gwapi_key = aws_response["value"]
    else:
        # Prompt the user for the API key
        gwapi_key = getpass.getpass(prompt='API key: ')

    return gwapi_key


def run_vulnerability_assessment(api_key, host, url):
    # Using the REST endpoint exposed by the step function
    scan_all_url = "{}/scan".format(url)
    session = requests.Session()
    session.headers.update({"X-Api-Key": api_key, "Content-Type": "application/json"})

    logging.info("Sending POST to {}".format(scan_all_url))
    response = session.post(scan_all_url, data='{"target":"' + host + '"}')
    if response.status_code == 200 and 'executionArn' in response.json() and 'startDate' in response.json():
        logging.info("Triggered scan of: {}".format(host))
        time.sleep(1)
        logging.info("Results will be emailed to your inbox when all scans run.")
    elif response.status_code == 403:
        logging.error("Invalid API key.")
    else:
        logging.error("Something went wrong. Ensure you have the correct API key and the service is operational.")

    session.close()


def download_assessment_results(api_key, arguments, url):
    download_url = "{}/results".format(url)
    session = requests.Session()
    session.headers.update({"X-Api-Key": api_key, "Accept": "application/gzip", "Content-Type": "application/json"})

    logging.info("Sending POST to {}".format(download_url))
    response = session.post(download_url, data='{"target":"' + arguments.fqdn + '"}', stream=True)

    if (response.status_code == 200 or response.status_code == 202 and response.headers["Content-Type"] == "application/gzip"):
        logging.info("Downloaded scan results for: {}, saving to disk...".format(arguments.fqdn))
        dirpath = arguments.results
        if not os.path.isdir(dirpath):
            os.mkdir(dirpath)
        path = os.path.join(dirpath, "{}.tar.gz".format(arguments.fqdn))
        with open(path, "wb") as out_file:
            shutil.copyfileobj(response.raw, out_file)
            logging.info("Scan results for {} are saved in the results folder.".format(arguments.fqdn))
        if response.status_code == 202:
            logging.warning("Not all scan results exist for the target. You should run the failed scans manually.")

        if arguments.extract:
            tdirpath = os.path.join(dirpath, "{}/".format(arguments.fqdn))
            if not os.path.isdir(dirpath):
                os.mkdir(tdirpath)
            with tarfile.open(path) as tar:
                tar.extractall(path=tdirpath)
                logging.info("Scan results for {} are extracted in the results folder.".format(arguments.fqdn))

    elif response.status_code == 403:
        logging.error("Invalid API key.")
    else:
        logging.error("No results found for: {}".format(arguments.fqdn))

    del response
    session.close()


def monitor_ct_logs(api_key, url):
    scan_all_url = "{}/scan".format(url)

    def print_callback(message, context):
        logging.debug("Message -> {}".format(message))

        if message['message_type'] == "certificate_update":
            all_domains = message['data']['leaf_cert']['all_domains']
            domain_patterns = [
                ".mozilla.com",
                ".mozilla.org",
                ".firefox.com",
            ]

            for fqdn in all_domains:
                for domain_pattern in domain_patterns:
                    # We want all legit FDQNs, but we can't scan wild-cards
                    if fqdn.endswith(domain_pattern) and ('*' not in fqdn):
                        session = requests.Session()
                        session.headers.update({"X-Api-Key": api_key, "Content-Type": "application/json"})
                        logging.info("Sending POST to {}".format(scan_all_url))
                        response = session.post(scan_all_url, data='{"target":"' + fqdn + '"}')
                        if response.status_code == 200 and 'executionArn' in response.json() and 'startDate' in response.json():
                            logging.info("Triggered scan of: {}".format(fqdn))
                            time.sleep(1)
                            logging.info("Results will be emailed to your inbox when all scans run.")
                        elif response.status_code == 403:
                            logging.error("Invalid API key.")
                            sys.exit(127)
                        else:
                            logging.error("Something went wrong. Ensure you have the correct API key and the service is operational.")
                            sys.exit(127)
                        session.close()

    certstream.listen_for_events(print_callback, url='wss://certstream.calidog.io/')


def choose_mode():
    parser = argparse.ArgumentParser(prog='va_ondemand.py')
    subparser = parser.add_subparsers()
    subparser.required = True
    subparser.dest = 'run OR download OR monitor'

    download_mode_parser = subparser.add_parser("download", help="Download results of an assessment for given host.")
    download_mode_parser.add_argument("fqdn", type=str, help="The target to scan", required=True)
    download_mode_parser.add_argument(
        "--profile",
        help="Provide the AWS Profile from your boto configuration",
        default=os.environ.get("AWS_PROFILE", None)
    )
    download_mode_parser.add_argument("--region", help="Provide the AWS region manually", default="us-west-2")
    download_mode_parser.add_argument("-x", "--extract", help="Auto extract results", action="store_true")
    download_mode_parser.add_argument("--results", help="Specify a results directory", default=os.path.join(os.getcwd(), "results/"))

    run_mode_parser = subparser.add_parser("run", help="Run a vulnerability assessment for given host.")
    run_mode_parser.add_argument("fqdn", type=str, help="The target to scan", required=True)
    run_mode_parser.add_argument(
        "--profile",
        help="Provide the AWS Profile from your boto configuration",
        default=os.environ.get("AWS_PROFILE", None)
    )
    run_mode_parser.add_argument("--region", help="Provide the AWS region manually", default="us-west-2")

    monitor_mode_parser = subparser.add_parser("monitor", help="Monitor CT logs and run a vulnerability assessment for a matching host.")
    monitor_mode_parser.add_argument(
        "--profile",
        help="Provide the AWS Profile from your boto configuration",
        default=os.environ.get("AWS_PROFILE", None)
    )
    monitor_mode_parser.add_argument("--region", help="Provide the AWS region manually", default="us-west-2")
    args = parser.parse_args()
    return args


def main():
    args = choose_mode(sys.argv[1:])

    # STEP 1: Load config
    config = load_config()
    vautomator_url = config['vautomator']['url']
    region = config['vautomator']['region']

    # STEP 2: Check if the target given is valid
    if not validate_target(args.fqdn):
        sys.exit(127)

    # STEP 3: We are good for target, let's check the profile OR API key
    api_key = check_authorization(args.profile, region)

    if args.run:
        run_vulnerability_assessment(api_key, args.fqdn, vautomator_url)
    elif args.download:
        download_assessment_results(api_key, args, vautomator_url)
    elif args.monitor:
        monitor_ct_logs(api_key, vautomator_url)
    else:
        logging.error("Unsupported mode. Exiting.")
        sys.exit(127)


if __name__ == "__main__":
    main()
