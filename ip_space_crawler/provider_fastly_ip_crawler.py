import logging
import re
import json

import requests
import jsonschema
import arrow

from ip_space_crawler import IPSpaceCrawlException
from ip_space_crawler import ProviderIPCrawler


class FastlyIPCrawler(ProviderIPCrawler):

    def __init__(self, logger):
        super().__init__(logger)

        self.source = "https://api.fastly.com/public-ip-list"
        self.provider_name = "Fastly"

    def get_ip_space(self):

        self.logger.info("Getting Fastly IP Space")

        fastly_ip_url = self.source

        fastly_ip_response = requests.get(fastly_ip_url)
        if fastly_ip_response.status_code != 200:
            raise IPSpaceCrawlException(f"Fastly crawl failed. Request to URL '{fastly_ip_url}' returned status code '{fastly_ip_response.status_code}', required status 200")

        with open("../schemas/cloudprovider_fastly_ip_space_schema.json") as f:
            jsonschema.validate(fastly_ip_response.json(), json.load(f))

        prefixes = fastly_ip_response.json()["addresses"] + fastly_ip_response.json()["ipv6_addresses"]


        return self.provider_name, {"prefixes": prefixes, "source": self.source, "date": str(arrow.utcnow()),  "successful":True}

