import logging
import re
import json

import requests
import jsonschema
import arrow

from ip_space_crawler import IPSpaceCrawlException
from ip_space_crawler import ProviderIPCrawler


class CloudFlareIPCrawler(ProviderIPCrawler):

    def __init__(self, logger):
        super().__init__(logger)

        self.source = "https://api.cloudflare.com/client/v4/ips"
        self.provider_name = "CloudFlare"

    def get_ip_space(self):

        self.logger.info("Getting CloudFlare IP Space")

        cf_ip_url = self.source

        cf_response = requests.get(cf_ip_url)
        if cf_response.status_code != 200:
            raise IPSpaceCrawlException(f"CloudFlare crawl failed. Request to URL '{cf_ip_url}' returned status code '{cf_response.status_code}', required status 200")

        with open("schemas/cloudprovider_cloudflare_ip_space_schema.json") as f:
            jsonschema.validate(cf_response.json(), json.load(f))

        prefixes = cf_response.json()["result"]["ipv4_cidrs"] + cf_response.json()["result"]["ipv6_cidrs"]

        return self.provider_name, {"prefixes": prefixes, "source": self.source, "date": str(arrow.utcnow()),  "successful":True}
