#!/usr/bin/env python3

### IMPORTS ###
import logging
import urllib.request
import urllib.error
import urllib.parse

### GLOBALS ###

### FUNCTIONS ###
# FIXME: Write some doc string stuff here.
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
        req_headers["Authorization"] = "Bearer {}".format(auth["token"])
    elif "username" in auth and "password" in auth:
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
