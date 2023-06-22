import json
import logging
import json
import logging
import sys
import urllib.parse
import os
import re
import netaddr

import requests
import arrow
import jsonschema
import s3fs


def prefixes_for_asns(asns):

    prefixes = []

    for asn in asns:
        asn = re.sub("^AS", "", asn, flags=re.IGNORECASE)
        asn_query_url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
        asn_response = requests.get(asn_query_url)
        if asn_response.status_code != 200:
            logging.error(f"Query for prefixes of ASN {asn} to {asn_query_url} returned status code {asn_response.status_code}. Expected 200. Skipping")
            continue
        for prefix in asn_response.json()["data"]["prefixes"]:
            prefixes.append(prefix["prefix"])

    return prefixes

class WhoHostsGetProviderIPSpaceException(Exception):
    pass


logging.basicConfig(format="[%(asctime)s] %(levelname)s in %(module)s: %(message)s", level=logging.INFO)


s3fs_client=None
if os.getenv("CLOUDCUBE_URL", None) is not None:
    logging.info("Setting up s3fs client with CloudCube info")
    os.environ["AWS_ACCESS_KEY_ID"] = os.getenv("CLOUDCUBE_ACCESS_KEY_ID")
    os.environ["AWS_SECRET_ACCESS_KEY"] = os.getenv("CLOUDCUBE_SECRET_ACCESS_KEY")
    s3fs_client = s3fs.S3FileSystem(anon=False)

provider_ip_space_file_url = os.environ['CLOUDPROVIDER_IP_SPACE_FILE']

logging.debug(f"provider_ip_space_file_url is '{provider_ip_space_file_url}'")

PROVIDER_IP_SPACE_FILE_SCHEMA_PATH = "schemas/whohosts_provider_ip_space_schema.json"

provider_space = dict()

provider_space['date'] = str(arrow.now())
provider_space["providers"] = dict()

#LINODE
logging.info("Getting Linode IP Space")
linode_ip_url = "https://geoip.linode.com/"
provider_space["providers"]["Linode"] = dict()
provider_space["providers"]["Linode"]["from"] = linode_ip_url

linode_ip_response = requests.get(linode_ip_url)
if linode_ip_response.status_code != 200:
    logging.error("Linode response did not return 200")
else:
    try:
        prefixes = []
        previous_line_good = False
        for row in linode_ip_response.text.split("\n"):
            if row.startswith("#"):
                continue
            columns = row.split(",")
            if len(columns) != 6:
                if not previous_line_good:
                    raise Exception(f"Unexpected number of columns in row. Expected 6 got {len(columns)}")
                else:
                    previous_line_good = False
                    continue
            prefixes.append(str(netaddr.IPNetwork(columns[0])))
            previous_line_good = True
    except netaddr.core.AddrFormatError as afe:
        logging.error(f"Couldn't parse Linode IP response from {linode_ip_url}. Response contained non-network address where network address was expected {afe}")
    except Exception as e:
        logging.error(f"Couldn't parse Linode IP response from {linode_ip_url}. Err is {e}")
    else:
        provider_space["providers"]["Linode"]["prefixes"] = prefixes

#NAMECHEAP
logging.info("Getting NameCheap prefixes")
namecheap_asns = ["AS22612"]
provider_space["providers"]["NameCheap"] = dict()
provider_space["providers"]["NameCheap"]["from"] = ",".join(namecheap_asns)
provider_space["providers"]["NameCheap"]["prefixes"] = prefixes_for_asns(namecheap_asns)

#Single hop
logging.info("Getting Singlehop prefixes")
singlehop_asns = ["AS32475"]
provider_space["providers"]["SingleHop"] = dict()
provider_space["providers"]["SingleHop"]["from"] = ",".join(singlehop_asns)
provider_space["providers"]["SingleHop"]["prefixes"] = prefixes_for_asns(singlehop_asns)

#Digital ocean
logging.info("Getting Digital Ocean prefixes")
digitalocean_asns = ["AS14061"]
provider_space["providers"]["Digital Ocean"] = dict()
provider_space["providers"]["Digital Ocean"]["from"] = ",".join(digitalocean_asns)
provider_space["providers"]["Digital Ocean"]["prefixes"] = prefixes_for_asns(digitalocean_asns)

#FASTLY
logging.info("Getting Fastly prefixes")
fastly_ip_url = "https://api.fastly.com/public-ip-list"
provider_space["providers"]["Fastly"] = dict()
provider_space["providers"]["Fastly"]["from"] = fastly_ip_url
fastly_ip_response = requests.get(fastly_ip_url)
if fastly_ip_response.status_code != 200:
    logging.error("Fastly response did not return 200")
else:
    try:
        with open("schemas/cloudprovider_fastly_ip_space_schema.json") as f:
            jsonschema.validate(fastly_ip_response.json(), json.load(f))
    except jsonschema.exceptions.ValidationError as ve:
        logging.error(f"Couldn't validate Fastly IP response from {fastly_ip_url}. Err is {ve}")
    else:
        provider_space["providers"]["Fastly"]["prefixes"] = fastly_ip_response.json()["addresses"] + \
                                                                fastly_ip_response.json()["ipv6_addresses"]

# CloudFlare
logging.info("Getting CloudFlare prefixes")
cf_ip_url = "https://api.cloudflare.com/client/v4/ips"
provider_space["providers"]["CloudFlare"] = dict()
provider_space["providers"]["CloudFlare"]["from"] = cf_ip_url

cf_response = requests.get(cf_ip_url)
if cf_response.status_code != 200:
    logging.error("CloudFlare response did not return 200")
else:
    try:
        with open("schemas/cloudprovider_cloudflare_ip_space_schema.json") as f:
            jsonschema.validate(cf_response.json(), json.load(f))
    except jsonschema.exceptions.ValidationError as ve:
        logging.error(f"Couldn't validate CloudFlare IP response from {cf_ip_url}. Err is {ve}")
    else:
        provider_space["providers"]["CloudFlare"]["prefixes"] = cf_response.json()["result"]["ipv4_cidrs"]+cf_response.json()["result"]["ipv6_cidrs"]

# Google
logging.info("Getting Google prefixes")
google_ip_url = "https://www.gstatic.com/ipranges/goog.json"

provider_space["providers"]["Google"] = dict()
provider_space["providers"]["Google"]["from"] = google_ip_url

g_response = requests.get(google_ip_url)
if g_response.status_code != 200:
    logging.error("Google response did not return 200")
else:
    try:
        with open("schemas/cloudprovider_google_ip_space_schema.json") as f:
            jsonschema.validate(g_response.json(), json.load(f))
    except jsonschema.exceptions.ValidationError as ve:
        logging.error(f"Couldn't validate Google IP response from {google_ip_url}. Err is {ve}")
    else:
        provider_space["providers"]["Google"]["prefixes"] = [prefix for prefixes in list(map(lambda p: list(p.values()), g_response.json()['prefixes'])) for prefix in prefixes]


# AWS
logging.info("Getting AWS prefixes")
provider_space["providers"]["AWS"] = dict()
aws_ip_url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
provider_space["providers"]["AWS"]["from"] = aws_ip_url

aws_response = requests.get(aws_ip_url)
if aws_response.status_code != 200:
    logging.error("AWS response did not return 200")
else:
    try:
        with open("schemas/cloudprovider_aws_ip_space_schema.json") as f:
            jsonschema.validate(aws_response.json(), json.load(f))
    except jsonschema.exceptions.ValidationError as ve:
        logging.error(f"Couldn't validate AWS IP response from {aws_ip_url}. Err is {ve}")
    else:
        provider_space["providers"]["AWS"]["prefixes"] = list()

        for prefix in aws_response.json()['prefixes']:
            provider_space["providers"]["AWS"]["prefixes"].append(prefix["ip_prefix"])
        for ipv6_prefix in aws_response.json()['ipv6_prefixes']:
            provider_space["providers"]["AWS"]['prefixes'].append(ipv6_prefix["ipv6_prefix"])


logging.debug(f"Loading provider IP space file schema file {PROVIDER_IP_SPACE_FILE_SCHEMA_PATH}")
try:
    with open(PROVIDER_IP_SPACE_FILE_SCHEMA_PATH) as ip_space_schema_fp:
        provider_ip_space_jsonschema = json.load(ip_space_schema_fp)
except Exception as e:
    logging.critical("Could not open or access provider IP space file schema file "
                     "'{{PROVIDER_IP_SPACE_FILE_SCHEMA_PATH}}' from '{os.getcwd()}'. Not going to write to provider "
                     "ip space file '{provider_ip_space_file_url}'")
    sys.exit(-1)


logging.debug(f"Saving provider IP space data to '{provider_ip_space_file_url}'")

jsonschema.validate(provider_space, provider_ip_space_jsonschema)

provider_file_url = os.environ['CLOUDPROVIDER_IP_SPACE_FILE']
logging.info(f"Loading cloud provider IP space from '{provider_file_url}'")

parsed_file_url = urllib.parse.urlparse(provider_ip_space_file_url)

if parsed_file_url.scheme == 'file':
    with open(parsed_file_url.path, 'w') as f:
        json.dump(provider_space, f)
elif parsed_file_url.scheme == 's3':
    if s3fs_client is None:
        raise WhoHostsGetProviderIPSpaceException("Cloud provider IP space file is set to be from s3 but s3 client not configured")
    with s3fs_client.open(parsed_file_url.path, 'w') as f:
        json.dump(provider_space, f)

else:
    raise WhoHostsGetProviderIPSpaceException(f"Cloud provider IP space file schema '{parsed_file_url.scheme}' not supported")


