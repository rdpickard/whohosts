import json
import sys
import re

import logging

import requests
import bs4
import jsonschema
import arrow

from ip_space_crawler import IPSpaceCrawlException
from ip_space_crawler import ProviderIPCrawler


class AzureIPCrawler(ProviderIPCrawler):

    def __init__(self, logger):
        super().__init__(logger)

        self.source = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"
        self.provider_name = "Azure"

    def get_ip_space(self):

        self.logger.info("Getting Azure IP Space")

        azure_ip_url = self.source
        prefixes = []

        azure_response = requests.get(azure_ip_url, headers={"User-Agent": "curl/7.71.1", "Accept": "*/*"})
        if azure_response.status_code != 200:
            raise IPSpaceCrawlException(f"Azure crawl failed. Request to URL '{azure_ip_url}' returned status code '{azure_response.status_code}', required status 200")

        soup = bs4.BeautifulSoup(azure_response.text, 'html.parser')

        download_link_urls = list()
        for m in re.findall(r'(https://download.microsoft.com/download/[a-zA-Z0-9\-/]*/ServiceTags_Public_\d+\.json)', str(soup)):
            download_link_urls.append(m)

        download_link_urls = list(set(download_link_urls))

        if len(download_link_urls) == 0:
            raise IPSpaceCrawlException(f"Could not find link to download Azure Service Tags JSON file from the Azure URL {azure_ip_url}")
        if len(download_link_urls) > 1:
            print(download_link_urls)
            raise IPSpaceCrawlException(f"Found multiple links to download Azure Service Tags JSON file from the Azure URL {azure_ip_url}. Require only one link to be present")

        service_tag_download_url = list(download_link_urls)[0]

        service_tag_dl_response = requests.get(service_tag_download_url)
        if service_tag_dl_response.status_code != 200:
            raise IPSpaceCrawlException(f"Azure crawl failed. Request to service tag URL '{service_tag_download_url}' returned status code '{service_tag_dl_response.status_code}', required status 200")

        service_tag_json = service_tag_dl_response.json()

        with open("../schemas/cloud_provider_azure_ip_space_schema.json") as f:
            jsonschema.validate(service_tag_json, json.load(f))

        for azure_feature in service_tag_json["values"]:
            prefixes += azure_feature["properties"]["addressPrefixes"]

        prefixes = list(set(prefixes))

        return self.provider_name, {"prefixes": prefixes, "source": azure_ip_url, "date": str(arrow.utcnow()), "successful":True}


if __name__ == '__main__':

    # set up the logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    stdout = logging.StreamHandler(sys.stdout)
    stdout.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s in %(module)s: %(message)s"))
    logger.addHandler(stdout)

    azure_crawler = AzureIPCrawler(logger)
    print(json.dumps(azure_crawler.get_ip_space(), indent=2, sort_keys=True))
