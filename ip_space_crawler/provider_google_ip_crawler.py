import logging
import re
import json

import requests
import jsonschema
import arrow

from ip_space_crawler import IPSpaceCrawlException
from ip_space_crawler import ProviderIPCrawler


class GCCIPCrawler(ProviderIPCrawler):

    def __init__(self, logger):
        super().__init__(logger)

        self.source = "https://www.gstatic.com/ipranges/goog.json"
        self.provider_name = "Google Cloud Compute"

    def get_ip_space(self):

        self.logger.info(f"Getting {self.provider_name} IP Space")

        google_ip_url = self.source

        g_response = requests.get(google_ip_url)
        if g_response.status_code != 200:
            raise IPSpaceCrawlException(f"{self.provider_name} crawl failed. Request to URL '{google_ip_url}' returned status code '{g_response.status_code}', required status 200")

        with open("../schemas/cloudprovider_google_ip_space_schema.json") as f:
            jsonschema.validate(g_response.json(), json.load(f))

        prefixes = [prefix for prefixes in list(map(lambda p: list(p.values()), g_response.json()['prefixes'])) for prefix in prefixes]

        return self.provider_name, {"prefixes": prefixes, "source": self.source, "date": str(arrow.utcnow()),  "successful":True}
