import json
import os
import argparse
import logging
import sys
import urllib.parse

import s3fs

missing=False
for missing_env_var in list(filter(lambda var_name: os.getenv(var_name, None) is None, ["CLOUDCUBE_URL", "CLOUDCUBE_ACCESS_KEY_ID", "CLOUDCUBE_SECRET_ACCESS_KEY", "CLOUDPROVIDER_IP_SPACE_FILE"])):
    print(f"missing required environment variable {missing_env_var}")
    missing=True
if missing:
    sys.exit(-1)

file_url = os.environ['CLOUDPROVIDER_IP_SPACE_FILE']

parsed_file_url = urllib.parse.urlparse(file_url)

if parsed_file_url.scheme != 's3':
    print(f"file url expected scheme 's3'. given scheme '{parsed_file_url.scheme}' in '{file_url}' not supported")

os.environ["AWS_ACCESS_KEY_ID"] = os.getenv("CLOUDCUBE_ACCESS_KEY_ID")
os.environ["AWS_SECRET_ACCESS_KEY"] = os.getenv("CLOUDCUBE_SECRET_ACCESS_KEY")
s3fs_client = s3fs.S3FileSystem(anon=False)

with s3fs_client.open(parsed_file_url.path, 'r') as f:
    file_json = json.load(f)

print(json.dumps(file_json, indent=2, sort_keys=True))