import logging
import re
import json

import arrow
import requests
import jsonschema

from ip_space_crawler import IPSpaceCrawlException
from ip_space_crawler import ProviderIPCrawler


class AWSIPCrawler(ProviderIPCrawler):

    def __init__(self, logger):
        super().__init__(logger)

        self.source = "https://ip-ranges.amazonaws.com/ip-ranges.json"
        self.provider_name = "AWS"

    def get_ip_space(self):

        self.logger.info("Getting AWS IP Space")

        aws_ip_url = self.source
        prefixes = []

        aws_response = requests.get(aws_ip_url)
        if aws_response.status_code != 200:
            raise IPSpaceCrawlException(f"AWS crawl failed. Request to URL '{aws_ip_url}' returned status code '{aws_response.status_code}', required status 200")

        with open("../schemas/cloudprovider_aws_ip_space_schema.json") as f:
            jsonschema.validate(aws_response.json(), json.load(f))

        for prefix in aws_response.json()['prefixes']:
            prefixes.append(prefix["ip_prefix"])
        for ipv6_prefix in aws_response.json()['ipv6_prefixes']:
            prefixes.append(ipv6_prefix["ipv6_prefix"])

        return self.provider_name, {"prefixes": prefixes, "source": aws_ip_url, "date": str(arrow.utcnow()), "successful":True}
