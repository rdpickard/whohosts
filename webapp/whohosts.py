import re
import json
import logging
import os
import urllib.parse
import sys

import flask
from flask import Flask, request, jsonify
import netaddr
import dns.resolver
import requests
import redis
import jsonschema
import s3fs

app = Flask(__name__)
app.logger.setLevel(logging.DEBUG)

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

ENV_VAR_REDIS_URL = "REDISCLOUD_URL"
PROVIDER_IP_SPACE_FILE_SCHEMA_PATH = "../schemas/whohosts_provider_ip_space_schema.json"

app.logger.debug(f"Loading provider IP space file schema file {PROVIDER_IP_SPACE_FILE_SCHEMA_PATH}")
try:
    with open(PROVIDER_IP_SPACE_FILE_SCHEMA_PATH) as ip_space_schema_fp:
        provider_ip_space_jsonschema = json.load(ip_space_schema_fp)
except Exception as e:
    app.logger.critical(f"Could not open or access provider IP space file schema file "
                        f"'{PROVIDER_IP_SPACE_FILE_SCHEMA_PATH}' from '{os.getcwd()}'. Can't start. Exiting")
    sys.exit(-1)


class WhoHostsException(Exception):
    pass


class CacheIfCacheCan:
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


def load_cloud_provider_ip_space_from_file():

    provider_file_url = os.getenv('CLOUDPROVIDER_IP_SPACE_FILE', None)
    if provider_file_url is None:
        raise WhoHostsException("Can't load cloud provider ip space, environment var CLOUDPROVIDER_IP_SPACE_FILE not set")

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

    app.config['cloud_providers_ip_space'] = cloud_providers_ip_space

    app.config['gui_provider_table'] = dict()
    for cloud_provider, provider_info in app.config['cloud_providers_ip_space']["providers"].items():
        app.config['gui_provider_table'][cloud_provider] = provider_info["meta"]["ui_description"]


s3fs_client=None
if os.getenv("CLOUDCUBE_URL", None) is not None:
    logging.info("Setting up s3fs client with CloudCube info")
    os.environ["AWS_ACCESS_KEY_ID"] = os.getenv("CLOUDCUBE_ACCESS_KEY_ID")
    os.environ["AWS_SECRET_ACCESS_KEY"] = os.getenv("CLOUDCUBE_SECRET_ACCESS_KEY")
    s3fs_client = s3fs.S3FileSystem(anon=False)

if os.getenv(ENV_VAR_REDIS_URL, None) is not None:
    redis_url = urllib.parse.urlparse(os.environ.get(ENV_VAR_REDIS_URL))
    app.logger.info(f"Setting up to use redis cache at {redis_url.hostname}")
    r = redis.Redis(host=str(redis_url.hostname),
                    port=redis_url.port,
                    password=redis_url.password)
    cache = CacheIfCacheCan(r)
else:
    app.logger.info(f"Environment variable '{ENV_VAR_REDIS_URL}' not set so not using redis caching")
    cache = CacheIfCacheCan(None)

load_cloud_provider_ip_space_from_file()

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
    return flask.render_template("index.jinja2", providers_table=app.config['gui_provider_table'])


@app.route("/<lookup_target_list>")
def lookup(lookup_target_list):

    hosting_table = dict()

    if flask.request.content_type is not None and flask.request.content_type.startswith('application/json'):
        return_json = True
    else:
        return_json = False

    lookup_targets = lookup_target_list.split(",")

    if len(lookup_targets) > 5:
        return_message = f"Max 5 targets in request. {len(lookup_targets)} provided"
        if return_json:
            return jsonify({"message": return_message}), 406
        else:
            return flask.render_template("index.jinja2", error_message=return_message,
                                         providers_table=app.config['gui_provider_table']), 406

    for lookup_target in lookup_targets:
        if not (re.match(ip_regex_complied, lookup_target) or re.match(hostname_regex_compiled, lookup_target)):
            return_message = f"Can't parse target '{lookup_target}'. Must be a hostname, IPv4 or IPv6 address"
            if return_json:
                return jsonify({"message": return_message}), 406
            else:
                return flask.render_template("index.jinja2", error_message=return_message,
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
            return flask.render_template("index.jinja2",
                                         error_message=f"DNS Servers must be IP addresses. Values "
                                                       f"{bad_servers_list} not usable",
                                         providers_table=app.config['gui_provider_table']), 406

    dns_query_all_servers = False
    if "dns_query_all_servers" in request.args.keys():
        if request.args["dns_query_all_servers"].lower() == "true":
            dns_query_all_servers = True

    for lookup_target in lookup_targets:

        ip_info = None

        if re.match(hostname_regex_compiled, lookup_target):
            if dns_query_all_servers and dns_servers is not None:
                for dns_server in dns_servers:
                    c_ip_info = resolve_host_ip_addresses(lookup_target, [dns_server], True)
                    if c_ip_info is not None:
                        if ip_info is None:
                            ip_info = []
                        ip_info = c_ip_info + ip_info
            else:
                ip_info = resolve_host_ip_addresses(lookup_target, dns_servers, True)
            hostname = lookup_target
        elif re.match(ip_regex_complied, lookup_target):
            ip_info = [{"ip_address": lookup_target, "dns_responder": None}]
            hostname = lookup_target
        else:
            return_message = f"Can't parse target '{lookup_target}'. Must be a hostname, IPv4 or IPv6 address", 406
            if return_json:
                return jsonify({"message": return_message}), 406
            else:
                return [flask.render_template("index.jinja2", error_message=return_message,
                                              providers_table=app.config['gui_provider_table']), 406]

        hosting_table[hostname] = dict()
        hosting_table[hostname]["ip_info"] = None

        if ip_info is not None:

            hosting_table[hostname]["ip_info"] = []

            for ip_dict in ip_info:

                ip_details = dict()
                ipaddress = netaddr.IPAddress(ip_dict["ip_address"])
                ip_details["ip_address"] = str(ipaddress)
                ip_details["dns_responder"] = ip_dict["dns_responder"]

                asn, prefix, holder = asn_info_for_ip(str(ipaddress))
                ip_details["asn"] = asn
                ip_details["as_prefix"] = prefix
                ip_details["as_holder"] = holder

                ip_details["cloud_provider"] = None
                ip_details["cloud_provider_prefix"] = None

                cloud_providers = []

                for cloud_provider, provider_info in app.config['cloud_providers_ip_space']["providers"].items():
                    provider_ipnetworks = provider_info["prefix_networks"]
                    for provider_ipnetwork in provider_ipnetworks:
                        if ipaddress in provider_ipnetwork:
                            cloud_providers.append((cloud_provider, str(provider_ipnetwork)))

                if len(cloud_providers) > 1:
                    logging.warning(f"more than one cloud provider for {hostname}")

                for cloud_provider in cloud_providers:
                    ip_details["cloud_provider"] = cloud_provider[0]
                    ip_details["cloud_provider_prefix"] = cloud_provider[1]

                hosting_table[hostname]["ip_info"].append(ip_details)

    if return_json:
        return hosting_table
    else:
        return flask.render_template("index.jinja2",
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


def resolve_host_ip_addresses(hostname, dns_server_ips, follow_cname=True):
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
                return resolve_host_ip_addresses(str(answers[0]), dns_server_ips, follow_cname=False)
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
        return None

    return all_ips


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
            return None, None, None
        if len(ni_doc["data"]["asns"]) > 1:
            raise WhoHostsException(
                f"RIPE ATLAS URL '{ripe_atlas_ni_url}' returned more than one ASN for IP '{ipaddress}'. "
                f"ANSs -> {','.join(ni_doc['data']['asns'])}. Expected only one ASN. Bailing")
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

    asn = ni_doc["data"]["asns"][0]
    prefix = ni_doc["data"]["prefix"]

    as_cache_key = f"ripe_as-overview_{ipaddress}"
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

    holder = as_doc["data"]["holder"]

    return asn, prefix, holder


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5050)
