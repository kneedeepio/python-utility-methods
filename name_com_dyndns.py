#!/usr/bin/env python3

### IMPORTS ###
import argparse
import json
import logging
import os
import sys
import urllib.request
import urllib.error
import urllib.parse

### GLOBALS ###

### FUNCTIONS ###
def make_api_request(host, method, path, data = None, is_data_json = False, auth = {}):
    # Handle the URL
    host_parts = urllib.parse.urlsplit(host)
    path_parts = urllib.parse.urlsplit(path)
    url_parts = urllib.parse.SplitResult(
        scheme = host_parts.scheme,
        netloc = host_parts.netloc,
        path = urllib.parse.quote(path_parts.path),
        query = urllib.parse.quote(path_parts.query, safe = "?=,&"),
        fragment = path_parts.fragment
    )
    req_url = url_parts.geturl()

    # Handle the headers
    req_headers = {}
    if is_data_json:
        req_headers["Content-Type"] = "application/json"
    else:
        req_headers["Content-Type"] = "text/plain"

    # Handle the data
    req_data = data.encode("utf-8") if data is not None else None

    # Handle the auth
    if "token" in auth:
        logging.debug("Using bearer token auth")
        req_headers["Authorization"] = "Bearer {}".format(auth["token"])
    elif "username" in auth and "password" in auth:
        logging.debug("Using basic auth")
        req_pwmanager = urllib.request.HTTPPasswordMgrWithPriorAuth()
        # FIXME: Should the URI in the password be the request URL, or just the hostname.
        req_pwmanager.add_password(None, req_url, auth["username"], auth["password"], is_authenticated = True)
        req_handler = urllib.request.HTTPBasicAuthHandler(req_pwmanager)
        req_opener = urllib.request.build_opener(req_handler)
        urllib.request.install_opener(req_opener)

    # Log all the fun
    logging.debug("req_url: %s", req_url)
    logging.debug("req_method: %s", method)
    logging.debug("req_headers: %s", req_headers)
    logging.debug("req_data: %s", req_data)

    # And make the request
    request = urllib.request.Request(req_url, data = req_data, headers = req_headers, method = method)
    resp = None
    try:
        with urllib.request.urlopen(request) as response:
            # Check the status and log
            # NOTE: response.status for Python >=3.9, change to response.code if Python <=3.8
            resp = response.read().decode("utf-8")
            logging.debug("  Response Status: %d, Response Body: %s", response.status, resp)
            logging.debug("Repository operation successful")
    except urllib.error.HTTPError as ex:
        logging.warning("Error (%d) for repository operation", ex.code)
        logging.debug("  response body: %s", ex.read().decode("utf-8"))
    except urllib.error.URLError as ex:
        logging.error("Request Failed (URLError): %s", ex.reason)
    return resp

### CLASSES ###

### MAIN ###
def main():
    parser_description = """
    Update a record at name.com to simulate DYNDNS functionality.
    """

    parser = argparse.ArgumentParser(description = parser_description, formatter_class = argparse.RawTextHelpFormatter)
    parser.add_argument("-v", "--verbose", action = "store_true")
    parser.add_argument("--username", default = os.getenv("NAME_COM_USERNAME", ""),
                        help = "Username for name.com account.")
    parser.add_argument("--token", default = os.getenv("NAME_COM_TOKEN", ""),
                        help = "API Token for name.com account.")
    parser.add_argument("--recordtype", default = os.getenv("NAME_COM_RECORDTYPE", "A"),
                        help = "Record type for the record to be updated.")
    parser.add_argument("--domain", default = os.getenv("NAME_COM_DOMAIN", ""),
                        help = "Domain name for the record to be updated.")
    parser.add_argument("--hostname", default = os.getenv("NAME_COM_HOSTNAME", ""),
                        help = "Hostname (shortname) for the record to be updated.")
    parser.add_argument("--recordid", default = os.getenv("NAME_COM_RECORDID", ""),
                        help = "Specify the ID for the record to be updated to save a API call.")
    parser.add_argument("--verifyid", action = "store_true",
                        help = "If the record ID is specified, verify the record ID with the record list.")

    args = parser.parse_args()

    # Set up logging
    logging.basicConfig(
        format = "%(asctime)s:%(levelname)s:%(name)s:%(funcName)s: %(message)s",
        level = logging.DEBUG if args.verbose else logging.INFO
    )
    logging.debug("Args: %s", args)

    # Making sure the values are set
    logging.info("Verifying Inputs")
    bailout = False
    if args.username == "":
        logging.error("Please set the username.")
        bailout = True
    if args.token == "":
        logging.error("Please set the API token.")
        bailout = True
    if args.domain == "":
        logging.error("Please set the domain name.")
        bailout = True
    if args.hostname == "" and args.recordid == "":
        logging.error("Please set the hostname and/or the record ID.")
        bailout = True
    if args.verifyid == True and (args.hostname == "" or args.recordid == ""):
        logging.error("Please set the hostname and record ID when verifying the record ID.")
        bailout = True
    if args.recordtype not in ["A"]:
        # FIXME: Currently limiting to "A" type records.  Could make this support "AAAA" later.
        logging.error("Invalid record type.  Please unset or set to 'A'.")
        bailout = True
    if bailout:
        sys.exit(1)

    # Get the external IP address using "https://www.ipify.org/"
    logging.info("Getting the external IP address")
    ipify_resp_json = make_api_request("https://api.ipify.org", "GET", "/?format=json")
    logging.debug("ipify_resp_json: %s", ipify_resp_json)
    ipify_resp_dict = json.loads(ipify_resp_json)
    logging.debug("ipify_resp_dict: %s", ipify_resp_dict)
    logging.info("  %s", ipify_resp_dict["ip"])

    # Get the list of domains from name.com
    record_dict = None
    name_com_auth = {
        "username": args.username,
        "password": args.token
    }
    if args.verifyid == True or args.recordid == "":
        logging.info("Getting the domain list")
        # NOTE: Page defaults to 1000 items, not planning on having that many records, so not going to implement paging.
        domainlist_url_path = "/v4/domains/{}/records".format(args.domain)
        domainlist_resp_json = make_api_request("https://api.name.com", "GET", domainlist_url_path, auth = name_com_auth)
        logging.debug("domainlist_resp_json: %s", domainlist_resp_json)
        domainlist_resp_dict = json.loads(domainlist_resp_json)
        logging.debug("domainlist_resp_dict: %s", domainlist_resp_dict)

        logging.info("Getting the record id")
        for item in domainlist_resp_dict["records"]:
            logging.debug("item: %s", item)
            if item["type"] == args.recordtype:
                if item["host"] == args.hostname:
                    record_dict = item
                    break
        logging.debug("record_dict: %s", record_dict)

        if record_dict is None:
            logging.error("Unable to find the correct record.")
            sys.exit(2)

        if args.verifyid == True:
            logging.info("Verifying the record ID")
            logging.debug("  args.recordid: (%s) %s",type(args.recordid), args.recordid)
            logging.debug("  record_dict['id']: (%s) %s",type(record_dict["id"]), record_dict["id"])
            if not str(args.recordid) == str(record_dict["id"]):
                logging.error("  Verification FAILED")
                sys.exit(3)

    # Get the record if it's not already set (e.g. only using the ID)
    if record_dict is None:
        logging.info("Getting the DNS record by ID")
        record_url_path = "/v4/domains/{}/records/{}".format(args.domain, args.recordid)
        record_resp_json = make_api_request("https://api.name.com", "GET", record_url_path, auth = name_com_auth)
        logging.debug("record_resp_json: %s", record_resp_json)
        record_resp_dict = json.loads(record_resp_json)
        logging.debug("record_resp_dict: %s", record_resp_dict)
        record_dict = record_resp_dict

    # Update the record with the latest and greatest IP
    if not record_dict["answer"] == ipify_resp_dict["ip"]:
        logging.info("IP address changed, updating.")
        record_url_path = "/v4/domains/{}/records/{}".format(record_dict["domainName"], record_dict["id"])
        record_data_dict = {
            "type": args.recordtype,
            "answer": ipify_resp_dict["ip"]
        }
        update_resp_json = make_api_request(
            "https://api.name.com",
            "PUT",
            record_url_path,
            data = json.dumps(record_data_dict),
            is_data_json = True,
            auth = name_com_auth
        )
        logging.debug("update_resp_json: %s", update_resp_json)
        if update_resp_json is None:
            logging.error("Failed to update record")
            sys.exit(4)
        logging.info("IP address updated successfully")
    else:
        logging.info("IP address already matches")

if __name__ == "__main__":
    main()
