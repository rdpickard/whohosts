import logging
import sys
import json
import urllib.parse
import os
import argparse

import jsonschema
import arrow
import s3fs

from ip_space_crawler import IPSpaceCrawlException

import provider_linode_ip_crawler
import provider_namecheap_ip_crawler
import provider_digialocean_ip_crawler
import provider_singlehop_ip_crawler
import provider_aws_ip_crawler
import provider_fastly_ip_crawler
import provider_cloudflare_ip_crawler
import provider_google_ip_crawler
import provider_azure_ip_crawler


def crawl_providers_ip_space(logger):

    # basic structure of the returned JSON. time stamp of now and a sub dict of each provider detail
    provider_space = dict()
    provider_space['date'] = str(arrow.now())
    provider_space['providers'] = dict()

    # Each of the classes, not instances, of a crawler per provider
    provider_crawler_classes = [provider_linode_ip_crawler.LinodeIPCrawler,
                                provider_namecheap_ip_crawler.NameCheapIPCrawler,
                                provider_digialocean_ip_crawler.DigitalOceanIPCrawler,
                                provider_singlehop_ip_crawler.SingleHopIPCrawler,
                                provider_aws_ip_crawler.AWSIPCrawler,
                                provider_fastly_ip_crawler.FastlyIPCrawler,
                                provider_cloudflare_ip_crawler.CloudFlareIPCrawler,
                                provider_google_ip_crawler.GCCIPCrawler,
                                provider_azure_ip_crawler.AzureIPCrawler]

    # Loop over each crawler class, create an instance, get the IP space for that provider, add it to the returned JSON
    for provider_crawler_class in provider_crawler_classes:
        try:
            logging.debug(provider_crawler_class)
            provider_crawler = provider_crawler_class(logger=logger)
            provider_name, ip_space_json = provider_crawler.get_ip_space()

            if provider_name in provider_space.keys():
                logger.warning(f"Provider key '{provider_name}' already exists in provider_space JSON. Possible naming collision. Skipping output from class '{provider_crawler_class}' ")
                continue

            # TODO Validate ip_space_json against schema

            provider_space['providers'][provider_name] = dict()
            provider_space['providers'][provider_name] = ip_space_json

            logger.info(f"{provider_crawler.provider_name} -> {provider_crawler.get_ip_space()}")
        except Exception as e:
            logging.error(e)

    # Validate the returned JSON is formatted correctly
    try:
        with open("../schemas/whohosts_provider_ip_space_schema.json") as ip_space_schema_fp:
            jsonschema.validate(provider_space, json.load(ip_space_schema_fp))
    except jsonschema.exceptions.ValidationError as ve:
        logging.critical(f"Provider IP space JSON validation failed '{ve}'. Crawl results not saved. Exiting")
        raise ve
    except jsonschema.exceptions.SchemaError as se:
        logging.critical(f"Provider IP space JSON validation failed because schema file had an err '{se}'. Crawl results not saved. Exiting")
        raise se
    except Exception as e:
        logging.critical(f"Provider IP space JSON validation failed because an unhandled err '{e}'. Crawl results not saved. Exiting")
        raise e

    return provider_space

if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        prog='crawl_providers',
        description='Gets IP space from several Cloud providers')
    parser.add_argument('-f', '--filename', default=None)
    parser.add_argument('-v', '--verbose', action='store_true', default=False)
    parser.add_argument('-q', '--quiet', action='store_true', default=False)
    parser.add_argument('-pp', '--prettyprint', action='store_true', default=False)
    args = parser.parse_args()

    # set up the logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if not args.quiet:
        stdout = logging.StreamHandler(sys.stdout)
        stdout.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s in %(module)s: %(message)s"))
        logger.addHandler(stdout)
    else:
        logger.handlers.clear()
        logger.disabled = True

    provider_ip_space = crawl_providers_ip_space(logger)

    provider_ip_space_destination_file = None

    if "CLOUDPROVIDER_IP_SPACE_FILE" in os.environ:
        provider_ip_space_destination_file = os.environ['CLOUDPROVIDER_IP_SPACE_FILE']
        logging.info(f"found destination URL {provider_ip_space_destination_file} in environment var 'CLOUDPROVIDER_IP_SPACE_FILE'")

    if args.filename is not None:
        provider_ip_space_destination_file = args.filename
        logging.info(f"found destination URL {provider_ip_space_destination_file} in command line args")

    if provider_ip_space_destination_file is None:
        if args.prettyprint:
            print(json.dumps(provider_ip_space, indent=2, sort_keys=True))
        else:
            print(json.dumps(provider_ip_space))

    else:
        parsed_file_url = urllib.parse.urlparse(provider_ip_space_destination_file)

        if parsed_file_url.scheme == 'file':
            with open(parsed_file_url.path, 'w') as f:
                json.dump(provider_ip_space, f)
        elif parsed_file_url.scheme == 's3':

            s3fs_client = None

            if os.getenv("CLOUDCUBE_URL", None) is not None:
                logging.info("Setting up s3fs client with CloudCube info")
                os.environ["AWS_ACCESS_KEY_ID"] = os.getenv("CLOUDCUBE_ACCESS_KEY_ID")
                os.environ["AWS_SECRET_ACCESS_KEY"] = os.getenv("CLOUDCUBE_SECRET_ACCESS_KEY")
                s3fs_client = s3fs.S3FileSystem(anon=False)

            if s3fs_client is None:
                raise IPSpaceCrawlException(
                    f"Destination file '{provider_ip_space_destination_file}' is indicated to be to s3 but environment is not configured to create s3 client")

            with s3fs_client.open(parsed_file_url.path, 'w') as f:
                json.dump(provider_ip_space, f)

        else:
            raise IPSpaceCrawlException(
                f"Cloud provider IP space file schema '{parsed_file_url.scheme}' not supported")



