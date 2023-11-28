import logging
import re

import requests
import arrow

class IPSpaceCrawlException(Exception):
    pass

class ProviderIPCrawler:

    provider_name = "NAME NOT SET"
    source = "SOURCE NOT SET"

    logger = None

    def __init__(self, logger):
        self.logger = logger

    def get_ip_space(self):
        return None

class ProviderIPASCrawler(ProviderIPCrawler):

    def prefixes_for_asns(self, asns):
        """
        Returns a list of IP CIDRs associate with ASNs. The IPs are gathered from RIPE's current known announced list.

        """

        prefixes = []

        # check that all the AS values are valid
        invalid_values = list(filter(lambda asn: re.match("^(AS)?[0-9]*$",str(asn)) is None, asns))
        if len(invalid_values) > 0:
            raise IPSpaceCrawlException(f"{self.provider_name} crawl failed. List of ASNs contained invalid values '{', '.join(invalid_values)}'")

        for asn in asns:
            asn = str(asn)
            asn = re.sub("^AS", "", asn, flags=re.IGNORECASE)
            asn_query_url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
            asn_response = requests.get(asn_query_url)
            if asn_response.status_code != 200:
                raise IPSpaceCrawlException( f"{self.provider_name} crawl failed.Query for prefixes of ASN {asn} to {asn_query_url} returned status code {asn_response.status_code}. Required 200.")

            if 'data' not in asn_response.json().keys() or 'prefixes' not in asn_response.json()["data"].keys():
                raise IPSpaceCrawlException( f"{self.provider_name} crawl failed. Query for prefixes of ASN {asn} to {asn_query_url} did not return JSON in expected format. Either 'data' or 'data.prefixes' key missing")

            for prefix in asn_response.json()["data"]["prefixes"]:
                prefixes.append(prefix["prefix"])

        return self.provider_name, {"prefixes": prefixes, "source": ",".join(asns), "date": str(arrow.utcnow()),  "successful":True}

    def get_ip_space(self):

        self.logger.info(f"Getting {self.provider_name} IP Space")

        return self.prefixes_for_asns(self.source)




