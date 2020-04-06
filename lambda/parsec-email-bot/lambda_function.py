"""
Your module description
"""
import re
import urllib3
import boto3
import os
import sys
import uuid
from urllib.parse import unquote_plus

s3_client = boto3.client('s3')
http = urllib3.PoolManager()

def lambda_handler(event, context):
    for record in event['Records']:
        bucket = record['s3']['bucket']['name']
        key = unquote_plus(record['s3']['object']['key'])
        tmpkey = key.replace('/', '')
        download_path = '/tmp/{}{}'.format(uuid.uuid4(), tmpkey)
        s3_client.download_file(bucket, key, download_path)
        
        textfile = open(download_path, 'r')
        text = textfile.read()
        textfile.close()
        
        regex = r"https:\/\/api.parsecgaming.com\b([-a-zA-Z0-9@:%_\+.~#?&//=\r\n]*)"
        foundLink = re.search(regex, text).group(0)
        foundLink = foundLink.replace("=\n", "").replace('=3D',"=")

        print(foundLink)
        r = http.request('GET', foundLink)
        print(r.status)
        
