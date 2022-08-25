import json
import logging

import requests
import arrow

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
    provider_space["providers"]["CloudFlare"]["prefixes"] = cf_response.json()["result"]["ipv4_cidrs"]+cf_response.json()["result"]["ipv6_cidrs"]

# Google
logging.info("Getting Google prefixes")

provider_space["providers"]["Google"] = dict()
provider_space["providers"]["Google"]["from"] = "https://www.gstatic.com/ipranges/goog.json"

g_response = requests.get("https://www.gstatic.com/ipranges/goog.json")
if g_response.status_code != 200:
    logging.error("Google response did not return 200")
else:
    provider_space["providers"]["Google"]["prefixes"] = [prefix for prefixes in list(map(lambda p: list(p.values()), g_response.json()['prefixes'])) for prefix in prefixes]


# AWS
logging.info("Getting AWS prefixes")
provider_space["providers"]["AWS"] = dict()
provider_space["providers"]["AWS"]["from"] = "https://ip-ranges.amazonaws.com/ip-ranges.json"

aws_response = requests.get("https://ip-ranges.amazonaws.com/ip-ranges.json")
if aws_response.status_code != 200:
    logging.error("AWS response did not return 200")
else:
    provider_space["providers"]["AWS"]["prefixes"] = list()

    for prefix in aws_response.json()['prefixes']:
        provider_space["providers"]["AWS"]["prefixes"].append(prefix["ip_prefix"])
    for ipv6_prefix in aws_response.json()['ipv6_prefixes']:
        provider_space["providers"]["AWS"]['prefixes'].append(ipv6_prefix["ipv6_prefix"])

with open('provider_ip_space.json', 'w') as f:
    json.dump(provider_space, f)
