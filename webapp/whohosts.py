import re
import json
import logging
import os
import urllib.parse
import sys
import datetime

import arrow
import flask
from flask import Flask, request, jsonify
from flask_mobility import Mobility
import netaddr
import dns.resolver
import requests
import redis
import jsonschema
import s3fs

# environment vars, not all are required to be set
ENV_VAR_NAME_CLOUDPROVIDER_IP_SPACE_FILE = "CLOUDPROVIDER_IP_SPACE_FILE"
ENV_VAR_NAME_REDIS_URL = "REDISCLOUD_URL"
ENV_VAR_NAME_CLOUDCUBE_URL = "CLOUDCUBE_URL"
ENV_VAR_NAME_CLOUDCUBE_ACCESS_KEY_ID = "CLOUDCUBE_ACCESS_KEY_ID"
ENV_VAR_NAME_CLOUDCUBE_SECRET_ACCESS_KEY = "CLOUDCUBE_SECRET_ACCESS_KEY"
ENV_VAR_NAME_LOGLEVEL = "LOGLEVEL"

required_env_vars = [ENV_VAR_NAME_CLOUDPROVIDER_IP_SPACE_FILE]

PROVIDER_IP_SPACE_FILE_SCHEMA_PATH = "../schemas/whohosts_provider_ip_space_schema.json"

hostname_regex = r'(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)'
hostname_regex_compiled = re.compile(hostname_regex)

ip_regex = r'((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|' \
           r'25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|' \
           r'(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}' \
           r'|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|' \
           r'(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|' \
           r'[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|' \
           r'(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|' \
           r'((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|' \
           r'(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|' \
           r'[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|' \
           r'(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|' \
           r'((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|' \
           r'[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|' \
           r'(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|' \
           r'((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|' \
           r'1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|' \
           r'1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))'
ip_regex_complied = re.compile(ip_regex)

app = Flask(__name__)
app.logger.setLevel(os.getenv(ENV_VAR_NAME_LOGLEVEL, logging.INFO))
Mobility(app)


class WhoHostsException(Exception):
    pass


class CacheIfCacheCan:
    """
    A wrapper around getting/setting to a redis back end, if configured. A convenience class so code doesn't have to
    repeat boilerplate logic to check if redis has been configured or not. If redis isn't configured getting will
    always return None and setting will just be ignored
    """
    _redis_interface = None

    def __init__(self, redis_interface):
        self._redis_interface = redis_interface

    def get(self, key, is_json=False):
        if self._redis_interface is None:
            return None
        else:
            value = self._redis_interface.get(key)
            if value is None:
                return None
            elif is_json:
                value = json.loads(value)

            return value

    def set(self, key, value, timeout=None, is_json=False):
        if self._redis_interface is None:
            pass
        else:
            if is_json:
                value = json.dumps(value)

            if timeout is None:
                self._redis_interface.set(key, value)
            else:
                self._redis_interface.set(key, value, timeout)


def refresh_cloud_provider_ip_space():

    loaded_cloud_ip_data_age_min = (arrow.utcnow() - app.config['cloud_providers_ip_space_date']) / datetime.timedelta(minutes=1)
    if loaded_cloud_ip_data_age_min > 10:
        app.logger.info("Refreshing cloud provider ip space")
        load_cloud_provider_ip_space_from_file()
    else:
        app.logger.info(f"Not resloading age is {loaded_cloud_ip_data_age_min}")


def load_cloud_provider_ip_space_from_file():
    """
    Load cloud provider ip space from the location specified by ENV_VAR_NAME_CLOUDPROVIDER_IP_SPACE_FILE into
    app config variable 'cloud_providers_ip_space'. Also adds 'gui_provider_table' to app config for rendering
    jinja templates with cloud provider information
    :return:
    """

    provider_file_url = os.getenv(ENV_VAR_NAME_CLOUDPROVIDER_IP_SPACE_FILE, None)
    if provider_file_url is None:
        raise WhoHostsException("Can't load cloud provider ip space, environment "
                                f"var {ENV_VAR_NAME_CLOUDPROVIDER_IP_SPACE_FILE} not set")

    logging.info(f"Loading cloud provider IP space from '{provider_file_url}'")

    parsed_file_url = urllib.parse.urlparse(provider_file_url)

    if parsed_file_url.scheme == 'file':
        with open(parsed_file_url.path, 'r') as f:
            provider_ip_space_data = json.load(f)
    elif parsed_file_url.scheme == 's3':
        if s3fs_client is None:
            raise WhoHostsException("Cloud provider IP space file is set to be from s3 but s3 client not configured")
        with s3fs_client.open(parsed_file_url.path, 'r') as f:
            provider_ip_space_data = json.load(f)

    else:
        raise WhoHostsException(f"Cloud provider IP space file schema '{parsed_file_url.scheme}' not supported")

    jsonschema.validate(provider_ip_space_data, provider_ip_space_jsonschema)

    cloud_providers_ip_space = provider_ip_space_data

    for cloud_provider, cloud_provider_info in cloud_providers_ip_space["providers"].items():
        cloud_provider_info["prefix_networks"] = list(
            map(lambda cidr: netaddr.IPNetwork(cidr), cloud_provider_info["prefixes"]))
        cloud_provider_info["meta"] = dict()
        cloud_provider_info["meta"][
            "ui_description"] = f"Across {len(cloud_provider_info['prefix_networks'])} known ranges"
        cloud_provider_info["meta"][
            "date_acquired"] = f"Across {len(cloud_provider_info['prefix_networks'])} known ranges"

    app.config['cloud_providers_ip_space'] = cloud_providers_ip_space
    app.config['cloud_providers_ip_space_date'] = arrow.get(provider_ip_space_data["date"])

    app.config['gui_provider_table'] = dict()
    for cloud_provider, provider_info in app.config['cloud_providers_ip_space']["providers"].items():
        app.config['gui_provider_table'][cloud_provider] = provider_info["meta"]["ui_description"]


@app.route('/css/<path:path>')
def send_css(path):
    return flask.send_from_directory('staticfiles/css', path)


@app.route('/js/<path:path>')
def send_js(path):
    return flask.send_from_directory('staticfiles/js', path)


@app.route('/fonts/<path:path>')
def send_font(path):
    return flask.send_from_directory('staticfiles/fonts', path)


@app.route('/media/<path:path>')
def send_media(path):
    return flask.send_from_directory('staticfiles/media', path)


@app.route('/favicon.ico')
def send_icon():
    return [None, 404]


@app.route('/provider/<provider_name>')
def provider(provider_name):
    if flask.request.content_type is not None and flask.request.content_type.startswith('application/json'):
        return_json = True
    else:
        return_json = False

    if provider_name not in app.config['cloud_providers_ip_space']["providers"].keys():
        message = "Provider not known"
        if return_json:
            return jsonify({"message": message}), 404
        else:
            return message, 404

    else:
        provider_data = dict()
        provider_data["name"] = provider_name
        provider_data["ip_data_from"] = app.config['cloud_providers_ip_space']["providers"][provider_name]["from"]
        provider_data["ip_data_gathered_date_utc"] = app.config['cloud_providers_ip_space']["date"]
        provider_data["ip_prefixes"] = list(
            map(lambda network: str(network),
                app.config['cloud_providers_ip_space']["providers"][provider_name]["prefixes"]))

        return jsonify(provider_data)


@app.route("/")
@app.route("/index.html")
@app.route("/index.htm")
def default_page():
    if flask.request.MOBILE:
        return flask.render_template("index_mobile.jinja2", providers_table=app.config['gui_provider_table'])
    else:
        return flask.render_template("index.jinja2", providers_table=app.config['gui_provider_table'])

@app.route("/<lookup_target_list>")
def lookup(lookup_target_list):

    # Log the lookup request in a way that is easier to find among other messages
    app.logger.info(f"Look up request for '{lookup_target_list}'")

    refresh_cloud_provider_ip_space()

    lookup_results = {
        "date": str(arrow.utcnow()),
        "data": {},
        "error_messages": [],
        "warning_messages": []
    }

    try:
        # Figure out if the response should be just the JSON data or HTML
        if flask.request.content_type is not None and flask.request.content_type.startswith('application/json'):
            return_json = True
            template = None
        else:
            return_json = False
            # HTML will be returned so figure out if the mobile or desktop template should be used
            if flask.request.MOBILE:
                template = "index_mobile.jinja2"
            else:
                template = "index.jinja2"

        # Split the targets to lookup
        lookup_targets = lookup_target_list.split(",")

        # make sure more than 5 targets haven't been requested
        if len(lookup_targets) > 5:
            # Don't process request, too many targets
            lookup_results["error_messages"].append(f"Max 5 targets in request. {len(lookup_targets)} provided")

        # make sure all the targets look like IP addresses or hostnames
        for lookup_target in lookup_targets:
            if not (re.match(ip_regex_complied, lookup_target) or re.match(hostname_regex_compiled, lookup_target)):
                lookup_results["error_messages"].append(f"Can't parse target '{lookup_target}'. Must be a hostname, IPv4 or IPv6 address")

        # Split the dns servers if specified
        if "dns_servers" in request.args.keys():
            dns_servers = request.args["dns_servers"].split(",")
        else:
            dns_servers = None

        for dns_server in dns_servers or []:
            if not re.match(ip_regex_complied, dns_server):
                lookup_results["error_messages"].append(f"DNS Servers must be IP addresses. Values {dns_server} not usable")

        # Do a query to each specified DNS server
        dns_query_all_servers = False
        if "dns_query_all_servers" in request.args.keys():
            if request.args["dns_query_all_servers"].lower() == "true":
                dns_query_all_servers = True

        if dns_query_all_servers:
            # make the list of dns servers in to an array of single element arrays
            # ie ['1.1.1.1', '8.8.8.8', '1.1.1.3'] => [['1.1.1.1'], ['8.8.8.8'], ['1.1.1.3']]
            dns_servers = [[dns_server] for dns_server in dns_servers]
        else:
            # make the list of dns servers in to a one element array of an array of all servers
            # ie ['1.1.1.1', '8.8.8.8', '1.1.1.3'] => [['1.1.1.1', '8.8.8.8', '1.1.1.3']]
            dns_servers = [dns_servers]


        # Some pre-condition failed, return an error
        if len(lookup_results["error_messages"]) > 0:
            if return_json:
                return jsonify(lookup_results), 406
            else:
                return flask.render_template(template,
                                             lookup_results=lookup_results,
                                             providers_table=app.config['gui_provider_table']), 406
    except Exception as e:
        return "Unrecoverable err in processing request error is {}".format(e), 500

    lookup_result_template = {
        "ip_address": None,
        "dns_responder": None,
        "asn": None,
        "as_prefix": None,
        "as_holder": None,
        "cloud_provider": None,
        "cloud_provider_prefix": None,
        "dns_indirection": None,
        "no_ip": None,
    }

    try:
        for lookup_target in lookup_targets:

            lookup_results["data"][lookup_target] = []

            for dns_server in dns_servers:
                try:
                    # Look for DNS redirection
                    hostname, dns_indirection = resolve_host_dns_indirection(lookup_target, dns_server)
                except dns.resolver.NXDOMAIN as nxd:
                    lookup_result = lookup_result_template.copy()
                    lookup_result["dns_responder"] = dns_server
                    app.logger.info("NXDomain {} found in DNS indirection".format(str(nxd.canonical_name)))
                    lookup_result["no_ip"] = "(no such domain {})".format(str(nxd.canonical_name))
                    lookup_results["data"][lookup_target].append(lookup_result.copy())
                    continue
                except dns.resolver.LifetimeTimeout as lt:
                    lookup_result = lookup_result_template.copy()
                    lookup_result["dns_responder"] = dns_server
                    app.logger.info("DNS server {} lookup for {} timed out".format(dns_server, str(lookup_target)))
                    lookup_result["no_ip"] = "DNS request looking for indirection to DNS server timed out"
                    lookup_results["data"][lookup_target].append(lookup_result.copy())
                    continue
                except dns.resolver.NoNameservers as nns:
                    lookup_result = lookup_result_template.copy()
                    lookup_result["dns_responder"] = dns_server
                    lookup_result["no_ip"] = "None of the configured name servers responded to DNS request looking for DNS indirection"
                    lookup_results["data"][lookup_target].append(lookup_result.copy())
                    continue
                except Exception as e:
                    app.logger.error("Unhandled exception '{}' in lookup endpoint when looking for DNS indirection. Lookup endpoint URL path is '{}'".format(e, lookup_target_list))
                    lookup_result = lookup_result_template.copy()
                    lookup_result["dns_responder"] = dns_server
                    lookup_result["no_ip"] = "Unexpected exception '{}' looking for DNS indirection".format(e)
                    lookup_results["data"][lookup_target].append(lookup_result.copy())
                    continue

                try:
                    # Look up A and AAA records for the hostname
                    hostname_a_aaaa_records = resolve_host_a_and_aaaa_records(hostname, dns_server)
                except dns.resolver.NXDOMAIN as nxd:
                    lookup_result = lookup_result_template.copy()
                    lookup_result["dns_responder"] = dns_server
                    lookup_result["no_ip"] = "NXDomain {}".format(str(nxd.canonical_name))
                    lookup_result["dns_indirection"] = dns_indirection
                    lookup_result["hostname"] = hostname
                    lookup_results["data"][lookup_target].append(lookup_result.copy())
                    continue
                except dns.resolver.LifetimeTimeout as lt:
                    lookup_result = lookup_result_template.copy()
                    lookup_result["dns_responder"] = dns_server
                    lookup_result["no_ip"] = "DNS request DNS server timed out"
                    lookup_result["dns_indirection"] = dns_indirection
                    lookup_result["hostname"] = hostname
                    lookup_results["data"][lookup_target].append(lookup_result.copy())
                    continue
                except dns.resolver.NoNameservers as nns:
                    lookup_result = lookup_result_template.copy()
                    lookup_result["dns_responder"] = dns_server
                    lookup_result[
                        "no_ip"] = "None of the configured name servers responded to DNS request"
                    lookup_result["dns_indirection"] = dns_indirection
                    lookup_result["hostname"] = hostname
                    lookup_results["data"][lookup_target].append(lookup_result.copy())
                    continue
                except Exception as e:
                    app.logger.error(
                        "Unhandled exception '{}' in lookup endpoint when looking for A and AAA records. Lookup endpoint URL path is '{}'".format(
                            e, lookup_target_list))
                    app.logger.exception(e)
                    lookup_result = lookup_result_template.copy()
                    lookup_result["dns_responder"] = dns_server
                    lookup_result["no_ip"] = "Unexpected exception '{}' looking for A and AAA records".format(e)
                    lookup_result["dns_indirection"] = dns_indirection
                    lookup_result["hostname"] = hostname
                    lookup_results["data"][lookup_target].append(lookup_result.copy())
                    continue

                # Loop through all of the A and AAA records and see where they fit in cloud provider and BGP space
                for hostname_a_aaaa_record in hostname_a_aaaa_records:

                    ip_address = hostname_a_aaaa_record[0]
                    responder_address = hostname_a_aaaa_record[1]

                    ip_network = netaddr.IPAddress(ip_address)

                    # IP addresses can be in more than one ASN, for example in the case of anycast'ing
                    asn_prefix, asns_and_holders = asn_info_for_ip(ip_address)
                    if asn_prefix is None or asns_and_holders is None:
                        # Some DNS servers return weird addresses like 0.0.0.0 when censoring access to sites
                        app.logger.info("IP address '{}' found for hostname '{}' of lookup target '{}' against dns servers '{}' is not in any ASN".format(
                            ip_address, hostname, lookup_target, dns_server
                        ))
                        asn_prefix = None
                        asns_and_holders = [(None, None)]

                    # compare the hostname IP to the IP ranges of cloud providers
                    cloud_providers = []
                    for cloud_provider, provider_info in app.config['cloud_providers_ip_space']["providers"].items():
                        provider_ipnetworks = provider_info["prefix_networks"]
                        for provider_ipnetwork in provider_ipnetworks:
                            if ip_network in provider_ipnetwork:
                                cloud_providers.append((cloud_provider, str(provider_ipnetwork)))
                    if len(cloud_providers) > 1:
                        # In theory only one cloud provider should be hosting an IP address but DNS and routing are easy to mess up
                        app.logger.info(
                            "IP address '{}' found for hostname '{}' of lookup target '{}' against dns servers '{}' is in multiple cloud providers IP space '{}'".format(
                                ip_address, hostname, lookup_target, dns_server, str(cloud_providers)
                            ))
                    if len(cloud_providers) == 0:
                        cloud_providers = [(None,None)]

                    # NOW create a lookup result for each IP record for the hostname and ASN and cloud providers that IP matches
                    for asn_and_holder in asns_and_holders:
                        asn = asn_and_holder[0]
                        as_holder = asn_and_holder[1]
                        for cloud_provider in cloud_providers:

                            cloud_provider_name = cloud_provider[0]
                            cloud_provider_prefix = cloud_provider[1]

                            lookup_result = lookup_result_template.copy()

                            lookup_result["ip_address"] = ip_address
                            lookup_result["dns_responder"] = responder_address
                            lookup_result["hostname"] = hostname

                            lookup_result["asn"] = asn
                            lookup_result["as_holder"] = as_holder
                            lookup_result["as_prefix"] = asn_prefix

                            lookup_result["cloud_provider_prefix"] = cloud_provider_prefix
                            lookup_result["cloud_provider"] = cloud_provider_name

                            lookup_result["dns_indirection"] = dns_indirection

                            lookup_results["data"][lookup_target].append(lookup_result)

    except Exception as ee:
        app.logger.error("Unhandled exception '{}' doing hostname lookup for request '{}'".format(ee, lookup_targets))
        logging.exception(ee)
        return "Unrecoverable err in doing lookup error is {}".format(ee), 500


    if return_json:
        return jsonify(lookup_results), 406
    else:
        return flask.render_template(template,
                                     lookup_results=lookup_results,
                                     providers_table=app.config['gui_provider_table']), 406


@app.route("/<lookup_target_list>")
def lookup_orig(lookup_target_list):

    refresh_cloud_provider_ip_space()

    hosting_table = dict()

    if flask.request.MOBILE:
        template = "index_mobile.jinja2"
    else:
        template = "index.jinja2"

    if flask.request.content_type is not None and flask.request.content_type.startswith('application/json'):
        return_json = True
    else:
        return_json = False

    app.logger.info(f"Look up request for '{lookup_target_list}'")

    lookup_targets = lookup_target_list.split(",")

    if len(lookup_targets) > 5:
        return_message = f"Max 5 targets in request. {len(lookup_targets)} provided"
        if return_json:
            return jsonify({"message": return_message}), 406
        else:
            return flask.render_template(template, error_message=return_message,
                                         providers_table=app.config['gui_provider_table']), 406

    for lookup_target in lookup_targets:
        if not (re.match(ip_regex_complied, lookup_target) or re.match(hostname_regex_compiled, lookup_target)):
            return_message = f"Can't parse target '{lookup_target}'. Must be a hostname, IPv4 or IPv6 address"
            if return_json:
                return jsonify({"message": return_message}), 406
            else:
                return flask.render_template(template, error_message=return_message,
                                             providers_table=app.config['gui_provider_table']), 406

    dns_servers = None
    if "dns_servers" in request.args.keys():
        dns_servers = request.args["dns_servers"].split(",")
        bad_servers = []
        for dns_server in dns_servers:
            if not re.match(ip_regex_complied, dns_server):
                bad_servers.append(dns_server)
        if len(bad_servers) > 0:
            bad_servers_list = ",".join(bad_servers)
            return flask.render_template(template,
                                         error_message=f"DNS Servers must be IP addresses. Values "
                                                       f"{bad_servers_list} not usable",
                                         providers_table=app.config['gui_provider_table']), 406

    dns_query_all_servers = False
    if "dns_query_all_servers" in request.args.keys():
        if request.args["dns_query_all_servers"].lower() == "true":
            dns_query_all_servers = True

    for lookup_target in lookup_targets:

        ip_info = None
        dns_indirection = None

        hostname = lookup_target

        if re.match(hostname_regex_compiled, lookup_target):
            if dns_query_all_servers and dns_servers is not None:
                for dns_server in dns_servers:
                    c_ip_info, dns_indirection = resolve_host_ip_addresses(lookup_target, [dns_server], True)
                    if c_ip_info is not None:
                        if ip_info is None:
                            ip_info = []
                        ip_info = c_ip_info + ip_info
            else:
                ip_info, dns_indirection = resolve_host_ip_addresses(lookup_target, dns_servers, True)
        elif re.match(ip_regex_complied, lookup_target):
            ip_info = [{"ip_address": lookup_target, "dns_responder": None, "dns_indirection": None}]
            hostname = lookup_target
        else:
            return_message = f"Can't parse target '{lookup_target}'. Must be a hostname, IPv4 or IPv6 address", 406
            if return_json:
                return jsonify({"message": return_message}), 406
            else:
                return [flask.render_template(template, error_message=return_message,
                                              providers_table=app.config['gui_provider_table']), 406]

        hosting_table[hostname] = dict()
        hosting_table[hostname]["ip_info"] = None

        if ip_info is not None:

            hosting_table[hostname]["ip_info"] = []

            for ip_dict in ip_info:

                ipaddress = netaddr.IPAddress(ip_dict["ip_address"])
                asn_prefix, asns_and_holders = asn_info_for_ip(str(ipaddress))

                if asn_prefix is None or asns_and_holders is None:
                    return_message = f"ASN lookup for IP address {str(ipaddress)} returned no ASNs!"
                    logging.warning(return_message)
                    if return_json:
                        return jsonify({"message": return_message}), 406
                    else:
                        return [flask.render_template(template, error_message=return_message,
                                                      providers_table=app.config['gui_provider_table']), 406]

                cloud_providers = []

                for cloud_provider, provider_info in app.config['cloud_providers_ip_space']["providers"].items():
                    provider_ipnetworks = provider_info["prefix_networks"]
                    for provider_ipnetwork in provider_ipnetworks:
                        if ipaddress in provider_ipnetwork:
                            cloud_providers.append((cloud_provider, str(provider_ipnetwork)))

                if len(cloud_providers) == 0:
                    cloud_providers.append((None, None))

                for asn_and_holder in asns_and_holders:
                    for cloud_provider in cloud_providers:

                        ip_details = dict()
                        ip_details["ip_address"] = str(ipaddress)
                        ip_details["dns_responder"] = ip_dict["dns_responder"]

                        ip_details["asn"] = asn_and_holder[0]
                        ip_details["as_prefix"] = asn_prefix
                        ip_details["as_holder"] = asn_and_holder[1]

                        ip_details["cloud_provider"] = cloud_provider[0]
                        ip_details["cloud_provider_prefix"] = cloud_provider[1]

                        ip_details["dns_indirection"] = dns_indirection

                        hosting_table[hostname]["ip_info"].append(ip_details)

    if return_json:
        return hosting_table
    else:
        return flask.render_template(template,
                                     hosting_table=hosting_table,
                                     providers_table=app.config['gui_provider_table'],
                                     dns_servers=" ".join(dns_servers or []),
                                     dns_query_all_servers=dns_query_all_servers)


def look_for_ip_in_provider_space(ip):
    provider_tuples = list()

    ipaddress = netaddr.IPAddress(ip)
    for cloud_provider, provider_ipnetworks in app.config['cloud_providers_ip_networks'].items():
        for provider_ipnetwork in provider_ipnetworks:
            if ipaddress in provider_ipnetwork:
                provider_tuples.append((cloud_provider, str(provider_ipnetwork)))

    return provider_tuples


def resolve_host_dns_indirection(hostname, dns_server_ips, record_indirection=None):

    if record_indirection is None:
        record_indirection = list()

    if dns_server_ips is None or len(dns_server_ips) == 0:
        dns_resolver = dns.resolver.Resolver()
    else:
        dns_resolver = dns.resolver.Resolver(configure=False)
        dns_resolver.nameservers = dns_server_ips

    try:
        cname_answers = dns_resolver.resolve(hostname, 'CNAME')

        if len(cname_answers) == 1:
            cnamed_host = str(cname_answers[0])
            record_indirection.append((hostname, "CNAME", cnamed_host))
            return resolve_host_dns_indirection(cnamed_host, dns_server_ips, record_indirection)
        elif len(cname_answers) > 1:
            err_message = "DNS lookup to DNS server {} for CNAME of hostname {} returned more than one CNAME records. This should not happen.".format(cname_answers.nameserver, hostname)
            app.logger.warning(err_message)
            raise WhoHostsException(err_message)
        elif len(cname_answers) == 0:
            warn_message = "DNS lookup to DNS server {} for CNAME of hostname {} returned zero CNAME records. Usually DNS python module raises NoAnswer exception in this case. Raising NoAnswer exception 'manually'".format(cname_answers.nameserver, hostname)
            app.logger.warning(warn_message)
            raise dns.resolver.NoAnswer()
    except dns.resolver.NoAnswer as na:
        # End of CNAMES
        return hostname, record_indirection


def resolve_host_a_and_aaaa_records(hostname, dns_server_ips):

    app.logger.info("A AAAA lookup {} {}".format(hostname, dns_server_ips))
    # Make the request to a specific DNS server or servers or use the configured host resolver
    if dns_server_ips is None or len(dns_server_ips) == 0:
        dns_resolver = dns.resolver.Resolver()
    else:
        dns_resolver = dns.resolver.Resolver(configure=False)
        dns_resolver.nameservers = dns_server_ips

    try:
        all_records = []
        try:
            v4_answers = dns_resolver.resolve(hostname, 'A')
            ip_v4_addresses = list(map(lambda v4_answer: str(v4_answer), v4_answers))
            for ip_v4_address in ip_v4_addresses:
                all_records.append((ip_v4_address, v4_answers.nameserver))
        except dns.resolver.NoAnswer as na:
            pass

        try:
            v6_answers = dns_resolver.resolve(hostname, 'AAAA')
            ip_v6_addresses = list(map(lambda v6_answer: str(v6_answer), v6_answers))
            for ip_v6_address in ip_v6_addresses:
                all_records.append((ip_v6_address, v6_answers.nameserver))
        except dns.resolver.NoAnswer as na:
            pass

    except dns.resolver.NXDOMAIN as nxd:
        pass
    except dns.resolver.LifetimeTimeout as lt:
        pass
    except dns.resolver.NoNameservers as nns:
        pass

    return  all_records


def resolve_host_ip_addresses(hostname, dns_server_ips, follow_cname=True, resolve_dns_indirection=None):
    if dns_server_ips is None or len(dns_server_ips) == 0:
        dns_resolver = dns.resolver.Resolver()
    else:
        dns_resolver = dns.resolver.Resolver(configure=False)
        dns_resolver.nameservers = dns_server_ips

    try:
        try:
            answers = dns_resolver.resolve(hostname, 'CNAME')
            if len(answers) > 1:
                cnames_list = ",".join(list(map(lambda answer: str(answer), answers)))
                raise WhoHostsException(
                    f"DNS resolution of {hostname} unexpectedly had more than one CNAME {cnames_list}. Bailing")
            elif len(answers) == 0:
                raise WhoHostsException(
                    f"DNS resolution of {hostname} unexpectedly answered for CNAME but returned no records. Bailing")
            elif not follow_cname:
                raise WhoHostsException(
                    f"DNS resolution of {hostname} has CNAME but follow_cname not set to True. Bailing")
            else:
                if resolve_dns_indirection is None:
                    resolve_dns_indirection = []
                resolve_dns_indirection.append((hostname, "CNAME", (str(answers[0]))))
                return resolve_host_ip_addresses(str(answers[0]), dns_server_ips, follow_cname=True, resolve_dns_indirection=resolve_dns_indirection)
        except dns.resolver.NoAnswer:
            pass

        all_ips = []

        try:
            v6_answers = dns_resolver.resolve(hostname, 'AAAA')
            ip_v6_addresses = list(map(lambda v6_answer: str(v6_answer), v6_answers))
            ip_v6_dns_responder = v6_answers.nameserver
            for ip_v6_address in ip_v6_addresses:
                all_ips.append({"ip_address": ip_v6_address, "dns_responder": ip_v6_dns_responder})
        except dns.resolver.NoAnswer:
            pass

        try:
            v4_answers = dns_resolver.resolve(hostname, 'A')
            ip_v4_addresses = list(map(lambda v4_answer: str(v4_answer), v4_answers))
            ip_v4_dns_responder = v4_answers.nameserver
            for ip_v4_address in ip_v4_addresses:
                all_ips.append({"ip_address": ip_v4_address, "dns_responder": ip_v4_dns_responder})
        except dns.resolver.NoAnswer:
            pass

    except dns.resolver.NXDOMAIN:
        return None, None
    except dns.resolver.LifetimeTimeout as lt:
        logging.info(f"Request to DNS server timed out, returning None. err {lt}")
        return None, None
    except dns.resolver.NoNameservers as nns:
        logging.info(f"Connection refused to nameserver {nns}")
        return None, None

    return all_ips, resolve_dns_indirection


def asn_info_for_ip(ipaddress):
    global cache

    ni_cache_key = f"ripe_network-info_{ipaddress}"
    ni_doc = cache.get(ni_cache_key, is_json=True)

    if ni_doc is None:

        ripe_atlas_ni_url = f"https://stat.ripe.net/data/network-info/data.json?resource={ipaddress}"
        ripe_atlas_ni_response = requests.get(ripe_atlas_ni_url)
        if ripe_atlas_ni_response.status_code != 200:
            raise WhoHostsException(
                f"Could not look up network info for IP '{ipaddress}' from RIPE ATLAS URL '{ripe_atlas_ni_url}'. "
                f"Request returned status {ripe_atlas_ni_response.status_code}, expected 200. Bailing")

        ni_doc = ripe_atlas_ni_response.json()

        if len(ni_doc["data"]["asns"]) == 0:
            return None, None

        if len(ni_doc["data"]["prefix"]) == 0:
            raise WhoHostsException(
                f"RIPE ATLAS URL '{ripe_atlas_ni_url}' returned no prefix in ASN {ni_doc['data']['asns'][0]} for IP "
                f"'{ipaddress}'. Expected only one ASN. Bailing")
        try:
            netaddr.IPNetwork(ni_doc["data"]["prefix"])
        except netaddr.core.AddrFormatError:
            raise WhoHostsException(
                f"RIPE ATLAS URL '{ripe_atlas_ni_url}' returned prefix {ni_doc['data']['prefix']} in "
                f"ASN {ni_doc['data']['asns'][0]} for IP '{ipaddress}' that doesn't look like a IP network. Bailing")

        cache.set(ni_cache_key, ni_doc, is_json=True)

    prefix = ni_doc["data"]["prefix"]
    holders = []
    asns_and_holders = []

    for asn in ni_doc["data"]["asns"]:

        as_cache_key = f"ripe_as-overview_{asn}"
        as_doc = cache.get(as_cache_key, is_json=True)

        if as_doc is None:

            ripe_atlas_as_url = f"https://stat.ripe.net/data/as-overview/data.json?resource={asn}"
            ripe_atlas_as_response = requests.get(ripe_atlas_as_url)
            if ripe_atlas_as_response.status_code != 200:
                raise WhoHostsException(
                    f"Could not look up as overview info for ASN '{asn}' from RIPE ATLAS URL '{ripe_atlas_as_url}'. "
                    f"Request returned status {ripe_atlas_as_response.status_code}, expected 200. Bailing")

            as_doc = ripe_atlas_as_response.json()
            cache.set(as_cache_key, as_doc, is_json=True)

        asns_and_holders.append((asn, as_doc["data"]["holder"]))
        holders.append(as_doc["data"]["holder"])

    return prefix, asns_and_holders


##########

# Make sure required env vars are set
for required_env_var in required_env_vars:
    if os.getenv(required_env_var, None) is None:
        logging.critical(f"Required environment variable '{required_env_var}' not set. Exiting")
        sys.exit(-1)

# Load the schema for the cloud ip space provider data from its file
try:
    with open(PROVIDER_IP_SPACE_FILE_SCHEMA_PATH) as ip_space_schema_fp:
        app.logger.debug(f"Loading provider IP space file schema file {PROVIDER_IP_SPACE_FILE_SCHEMA_PATH}")
        provider_ip_space_jsonschema = json.load(ip_space_schema_fp)
except Exception as e:
    app.logger.critical(f"Could not open or access provider IP space file schema file "
                        f"'{PROVIDER_IP_SPACE_FILE_SCHEMA_PATH}' from '{os.getcwd()}'. Can't start. Exiting")
    sys.exit(-1)

# If CloudCube (heroku add-on) is configured use s3 for the cloud ip space provider data
s3fs_client = None
if os.getenv(ENV_VAR_NAME_CLOUDCUBE_URL, None) is not None:
    logging.info("Setting up s3fs client with CloudCube info")
    os.environ["AWS_ACCESS_KEY_ID"] = os.getenv(ENV_VAR_NAME_CLOUDCUBE_ACCESS_KEY_ID)
    os.environ["AWS_SECRET_ACCESS_KEY"] = os.getenv(ENV_VAR_NAME_CLOUDCUBE_SECRET_ACCESS_KEY)
    s3fs_client = s3fs.S3FileSystem(anon=False)

# If redis is configured set up "cache" to use it
if os.getenv(ENV_VAR_NAME_REDIS_URL, None) is not None:
    redis_url = urllib.parse.urlparse(os.environ.get(ENV_VAR_NAME_REDIS_URL))
    app.logger.info(f"Setting up to use redis cache at {redis_url.hostname}")
    r = redis.Redis(host=str(redis_url.hostname),
                    port=redis_url.port,
                    password=redis_url.password)
    cache = CacheIfCacheCan(r)
else:
    app.logger.info(f"Environment variable '{ENV_VAR_NAME_REDIS_URL}' not set so not using redis caching")
    cache = CacheIfCacheCan(None)

# Load the provider ip infor before processing requests
load_cloud_provider_ip_space_from_file()


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5050)
