import logging
import re

import requests
import netaddr
import arrow

from ip_space_crawler import IPSpaceCrawlException
from ip_space_crawler import ProviderIPCrawler


class LinodeIPCrawler(ProviderIPCrawler):

    def __init__(self, logger):
        super().__init__(logger)

        self.source = "https://geoip.linode.com/"
        self.provider_name = "Linode"

    def get_ip_space(self):

        self.logger.info("Getting Linode IP Space")

        linode_ip_url = self.source
        prefixes = []

        linode_ip_response = requests.get(linode_ip_url) # This could raise exceptions expected to be handled by calling code
        if linode_ip_response.status_code != 200:
            raise IPSpaceCrawlException(f"Linode crawl failed. Request to URL '{linode_ip_url}' returned status code '{linode_ip_response.status_code}', required status 200")

        try:
            found_match = False

            ip_line_regex = re.compile(r'^(?P<CIDR>([0-9]{1,3}\.){3}[0-9]{1,3}($|/(\d*))),[a-zA-Z0-9]*,[a-zA-Z0-9\-]*,[a-zA-Z0-9\-]*,')

            for row in linode_ip_response.text.split("\n"):

                matched_line = re.match(ip_line_regex, row)
                if matched_line is None:
                    continue

                found_match = True
                prefixes.append(str(netaddr.IPNetwork(matched_line.group('CIDR'))))
        except netaddr.core.AddrFormatError as afe:
            raise IPSpaceCrawlException(f"Linode crawl failed. Couldn't parse Linode IP response from '{linode_ip_url}'. Response contained non-network address where network address was expected {afe}")
        except Exception as e:
            raise IPSpaceCrawlException(f"Linode crawl failed. Couldn't parse Linode IP response from {linode_ip_url}. Err is {e}")

        if not found_match:
            raise IPSpaceCrawlException(f"Linode crawl failed. Didn't find a single line in response in expected format")

        return self.provider_name, {"prefixes": prefixes, "source": self.source, "date": str(arrow.utcnow()),  "successful":True}

