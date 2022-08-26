import re
import json
import logging
import os

import flask
from flask import Flask, request, jsonify
import netaddr
import dns.resolver
import requests
import redis

app = Flask(__name__)

hostname_regex = r'(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)'
hostname_regex_compiled = re.compile(hostname_regex)

ip_regex = r'((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))'
ip_regex_complied = re.compile(ip_regex)

ENVVAR_REDIS_HOST_NAME = "redis_cache_host_name"
ENVVAR_REDIS_HOST_PORT = "redis_cache_host_port"
ENVVAR_REDIS_DB_ID = "redis_cache_db_id"


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


with open('../provider_ip_space.json', 'r') as f:
    provider_ip_space_data = json.load(f)

cloud_providers_ip_space = provider_ip_space_data["providers"]

cloud_providers_ip_networks = dict()
for cloud_provider, cloud_provider_info in cloud_providers_ip_space.items():
    print(cloud_provider)
    ip_space = cloud_provider_info["prefixes"]
    cloud_providers_ip_networks[cloud_provider] = list(map(lambda cidr: netaddr.IPNetwork(cidr), ip_space))

providers_table = dict()
for cloud_provider, ip_space in cloud_providers_ip_networks.items():
    size = sum(map(lambda ipnet: ipnet.size, ip_space))
    providers_table[cloud_provider] = f"Across {len(ip_space)} known ranges"


if os.environ.get(ENVVAR_REDIS_HOST_NAME, None) is not None:
    r = redis.Redis(host='localhost',
                    port=os.environ.get(ENVVAR_REDIS_HOST_PORT, 6379),
                    db=os.environ.get(ENVVAR_REDIS_DB_ID, 0))
    cache = CacheIfCacheCan(r)
else:
    cache = CacheIfCacheCan(None)


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


@app.route('/provider/<provider_name>')
def provider(provider_name):

    if flask.request.content_type is not None and flask.request.content_type.startswith('application/json'):
        return_json=True
    else:
        return_json=False

    if provider_name not in cloud_providers_ip_networks:
        message = "Provider not known"
        if return_json:
            return jsonify({"message": message}), 404
        else:
            return message, 404

    else:
        provider_data = dict()
        provider_data["name"] = provider_name
        provider_data["ip_data_from"] = provider_ip_space_data["providers"][provider_name]["from"]
        provider_data["ip_data_gathered_date_utc"] = provider_ip_space_data["date"]
        provider_data["ip_prefixes"] = list(map(lambda network: str(network), cloud_providers_ip_networks[provider_name]))

        return jsonify(provider_data)

@app.route("/")
@app.route("/index.html")
@app.route("/index.htm")
def default_page():
    return flask.render_template("index.jinja2", providers_table=providers_table)


@app.route("/<lookup_target_list>")
def lookup(lookup_target_list):

    hosting_table = dict()

    if flask.request.content_type is not None and flask.request.content_type.startswith('application/json'):
        return_json=True
    else:
        return_json=False

    lookup_targets = lookup_target_list.split(",")
    if len(lookup_targets) > 5:
        return_message = f"Max 5 targets in request. {len(lookup_targets)} provided"
        if return_json:
            return jsonify({"message": return_message}), 406
        else:
            return flask.render_template("index.jinja2", error_message=return_message, providers_table=providers_table), 406

    for lookup_target in lookup_targets:
        if not (re.match(ip_regex_complied, lookup_target) or re.match(hostname_regex_compiled, lookup_target)):
            return_message = f"Can't parse target '{lookup_target}'. Must be a hostname, IPv4 or IPv6 address"
            if return_json:
                return jsonify({"message": return_message}), 406
            else:
                return flask.render_template("index.jinja2", error_message=return_message, providers_table=providers_table), 406

    for lookup_target in lookup_targets:

        if re.match(hostname_regex_compiled, lookup_target):
            ips = resolve_host_ip_addresses(lookup_target, None, True)
            hostname = lookup_target
        elif re.match(ip_regex_complied, lookup_target):
            ips = [lookup_target]
            hostname = lookup_target
        else:
            return_message = f"Can't parse target '{lookup_target}'. Must be a hostname, IPv4 or IPv6 address", 406
            if return_json:
                return jsonify({"message": return_message}), 406
            else:
                return flask.render_template("index.jinja2", error_message=return_message, providers_table=providers_table), 406

        hosting_table[hostname] = dict()

        if ips is not None:
            for ip in ips:
                ipaddress = netaddr.IPAddress(ip)
                hosting_table[hostname][ip] = dict()

                asn, prefix, holder = asn_info_for_ip(ip)
                hosting_table[hostname][ip]["as"] = {"asn": asn, "prefix": prefix, "holder": holder}

                hosting_table[hostname][ip]["cloud_providers"] = []
                for provider, provider_ipnetworks in cloud_providers_ip_networks.items():
                    for provider_ipnetwork in provider_ipnetworks:
                        if ipaddress in provider_ipnetwork:
                            hosting_table[hostname][ip]["cloud_providers"].append((provider, str(provider_ipnetwork)))

    if return_json:
        return hosting_table
    else:
        return flask.render_template("index.jinja2", hosting_table=hosting_table, providers_table=providers_table)


def look_for_ip_in_provider_space(ip):

    provider_tuples = list()

    ipaddress = netaddr.IPAddress(ip)
    for provider, provider_ipnetworks in cloud_providers_ip_networks.items():
        for provider_ipnetwork in provider_ipnetworks:
            if ipaddress in provider_ipnetwork:
                provider_tuples.append((provider, str(provider_ipnetwork)))

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
        except dns.resolver.NoAnswer as na:
            pass

        ip_v4_addresses = []
        ip_v6_addresses = []

        try:
            v6_answers = dns_resolver.resolve(hostname, 'AAAA')
            ip_v6_addresses = list(map(lambda v6_answer: str(v6_answer), v6_answers))
        except dns.resolver.NoAnswer as na:
            pass

        try:
            v4_answers = dns_resolver.resolve(hostname, 'A')
            ip_v4_addresses = list(map(lambda v4_answer: str(v4_answer), v4_answers))
        except dns.resolver.NoAnswer as na:
            pass

    except dns.resolver.NXDOMAIN as nxd:
        return None

    return ip_v4_addresses + ip_v6_addresses


def asn_info_for_ip(ipaddress):

    global cache

    ni_cache_key = f"ripe_network-info_{ipaddress}"
    ni_doc = cache.get(ni_cache_key, is_json=True)

    if ni_doc is None:

        ripe_atlas_ni_url = f"https://stat.ripe.net/data/network-info/data.json?resource={ipaddress}"
        ripe_atlas_ni_response = requests.get(ripe_atlas_ni_url)
        if ripe_atlas_ni_response.status_code != 200:
            raise WhoHostsException(f"Could not look up network info for IP '{ipaddress}' from RIPE ATLAS URL '{ripe_atlas_ni_url}'. Request returned status {ripe_atlas_ni_response.status_code}, expected 200. Bailing")

        ni_doc = ripe_atlas_ni_response.json()

        if len(ni_doc["data"]["asns"]) == 0:
            return None, None, None
        if len(ni_doc["data"]["asns"]) > 1:
            raise WhoHostsException(f"RIPE ATLAS URL '{ripe_atlas_ni_url}' returned more than one ASN for IP '{ipaddress}'. ANSs -> {','.join(ni_doc['data']['asns'])}. Expected only one ASN. Bailing")
        if len(ni_doc["data"]["prefix"]) == 0:
            raise WhoHostsException(f"RIPE ATLAS URL '{ripe_atlas_ni_url}' returned no prefix in ASN {ni_doc['data']['asns'][0]} for IP '{ipaddress}'. Expected only one ASN. Bailing")
        try:
            netaddr.IPNetwork(ni_doc["data"]["prefix"])
        except netaddr.core.AddrFormatError:
            raise WhoHostsException(f"RIPE ATLAS URL '{ripe_atlas_ni_url}' returned prefix {ni_doc['data']['prefix']} in ASN {ni_doc['data']['asns'][0]} for IP '{ipaddress}' that doesn't look like a IP network. Bailing")

        cache.set(ni_cache_key, ni_doc, is_json=True)

    asn = ni_doc["data"]["asns"][0]
    prefix = ni_doc["data"]["prefix"]

    as_cache_key = f"ripe_as-overview_{ipaddress}"
    as_doc = cache.get(as_cache_key, is_json=True)

    if as_doc is None:

        ripe_atlas_as_url = f"https://stat.ripe.net/data/as-overview/data.json?resource={asn}"
        ripe_atlas_as_response = requests.get(ripe_atlas_as_url)
        if ripe_atlas_as_response.status_code != 200:
            raise WhoHostsException(f"Could not look up as overview info for ASN '{asn}' from RIPE ATLAS URL '{ripe_atlas_as_url}'. Request returned status {ripe_atlas_as_response.status_code}, expected 200. Bailing")

        as_doc = ripe_atlas_as_response.json()
        cache.set(as_cache_key, as_doc, is_json=True)

    holder = as_doc["data"]["holder"]

    return asn, prefix, holder


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5050)
