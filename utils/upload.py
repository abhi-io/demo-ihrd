# -*- coding: utf-8 -*-
import mimetypes
import socket

import boto3
from boto.s3 import connect_to_region
from boto.s3.key import Key
from boto3.s3.transfer import TransferConfig
from botocore.config import Config

from ihrd import settings
from ihrd.settings import logger

ACCESS_KEY = settings.S3_ACCESS_KEY
SECRET_KEY = settings.S3_SECRET_KEY
bucket_name = settings.BUCKET_NAME


socket.getaddrinfo("localhost", 8080)


def get_presigned_url(s3_file):
    s3 = boto3.client(
        "s3",
        aws_access_key_id=ACCESS_KEY,
        aws_secret_access_key=SECRET_KEY,
        config=Config(region_name="ap-south-1"),
    )

    url = s3.generate_presigned_url(
        "get_object",
        Params={
            "Bucket": bucket_name,
            "Key": s3_file,
        },
        ExpiresIn=3600,
    )
    return url


def upload_file_to_s3(file_name, file):
    logger.info("-------------------inside upload-------")
    conn = connect_to_region(
        "ap-south-1", aws_access_key_id=ACCESS_KEY, aws_secret_access_key=SECRET_KEY
    )
    b = conn.get_bucket(bucket_name)

    mime = mimetypes.guess_type(file_name)[0]
    file.seek(0)

    k = Key(b)
    k.key = file_name
    k.set_metadata("Content-Type", mime)
    k.set_contents_from_file(file)
    k.close()
    url = get_presigned_url(file_name)
    print(url)
    return url


def upload_file_to_s3_in_parts(file_name, local_path):

    logger.info("inside multi part upload--------------------------")

    s3_client = boto3.client(
        "s3",
        region_name="ap-south-1",
        aws_access_key_id=ACCESS_KEY,
        aws_secret_access_key=SECRET_KEY,
    )

    config = TransferConfig(
        multipart_threshold=1024 * 25,
        max_concurrency=10,
        multipart_chunksize=1024 * 25,
        use_threads=True,
    )
    mime = mimetypes.guess_type(file_name)[0]
    s3_client.upload_file(
        local_path,
        bucket_name,
        file_name,
        ExtraArgs={"ContentType": mime},
        Config=config,
    )
    url = get_presigned_url(file_name)
    return url
