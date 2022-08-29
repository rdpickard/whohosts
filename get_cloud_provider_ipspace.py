import json
import logging
import json
import logging
import sys
import urllib.parse
import os

import requests
import arrow
import jsonschema
import s3fs


class WhoHostsGetProviderIPSpaceException(Exception):
    pass


logging.basicConfig(format="[%(asctime)s] %(levelname)s in %(module)s: %(message)s", level=logging.DEBUG)


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

# CloudFlare
logging.info("Getting CloudFlare prefixes")
provider_space["providers"]["CloudFlare"] = dict()
provider_space["providers"]["CloudFlare"]["from"] = "https://api.cloudflare.com/client/v4/ips"

cf_response = requests.get("https://api.cloudflare.com/client/v4/ips")
if cf_response.status_code != 200:
    logging.error("CloudFlare response did not return 200")
else:
    with open("schemas/cloudprovider_cloudflare_ip_space_schema.json") as f:
        jsonschema.validate(cf_response.json(), json.load(f))
    provider_space["providers"]["CloudFlare"]["prefixes"] = cf_response.json()["result"]["ipv4_cidrs"]+cf_response.json()["result"]["ipv6_cidrs"]

# Google
logging.info("Getting Google prefixes")

provider_space["providers"]["Google"] = dict()
provider_space["providers"]["Google"]["from"] = "https://www.gstatic.com/ipranges/goog.json"

g_response = requests.get("https://www.gstatic.com/ipranges/goog.json")
if g_response.status_code != 200:
    logging.error("Google response did not return 200")
else:
    with open("schemas/cloudprovider_google_ip_space_schema.json") as f:
        jsonschema.validate(g_response.json(), json.load(f))
    provider_space["providers"]["Google"]["prefixes"] = [prefix for prefixes in list(map(lambda p: list(p.values()), g_response.json()['prefixes'])) for prefix in prefixes]


# AWS
logging.info("Getting AWS prefixes")
provider_space["providers"]["AWS"] = dict()
provider_space["providers"]["AWS"]["from"] = "https://ip-ranges.amazonaws.com/ip-ranges.json"

aws_response = requests.get("https://ip-ranges.amazonaws.com/ip-ranges.json")
if aws_response.status_code != 200:
    logging.error("AWS response did not return 200")
else:
    with open("schemas/cloudprovider_aws_ip_space_schema.json") as f:
        jsonschema.validate(aws_response.json(), json.load(f))
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

sys.exit()

if parsed_file_url.scheme == 'file':
    with open(parsed_file_url.path, 'r') as f:
        json.dump(provider_space, f)
elif parsed_file_url.scheme == 's3':
    if s3fs_client is None:
        raise WhoHostsGetProviderIPSpaceException("Cloud provider IP space file is set to be from s3 but s3 client not configured")
    with s3fs_client.open(parsed_file_url.path, 'w') as f:
        json.dump(provider_space, f)

else:
    raise WhoHostsGetProviderIPSpaceException(f"Cloud provider IP space file schema '{parsed_file_url.scheme}' not supported")


