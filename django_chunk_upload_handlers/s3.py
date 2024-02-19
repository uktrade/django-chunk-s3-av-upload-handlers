import concurrent.futures
import logging
import pathlib
import uuid
from concurrent.futures import (
    wait,
    ThreadPoolExecutor,
)

from boto3 import client as boto3_client
from django.conf import settings
from django.core.files.uploadhandler import (
    FileUploadHandler,
    UploadFileException,
)
from django.utils import timezone
from storages.backends.s3boto3 import (
    S3Boto3Storage,
    S3Boto3StorageFile,
)

from django_chunk_upload_handlers.util import check_required_setting
from django_chunk_upload_handlers.clam_av import FileWithVirus, VirusFoundInFileException


logger = logging.getLogger(__name__)


class AbortS3UploadException(UploadFileException):
    pass


# AWS
AWS_ACCESS_KEY_ID = getattr(settings,
                            "CHUNK_UPLOADER_AWS_ACCESS_KEY_ID",
                            getattr(settings, "AWS_ACCESS_KEY_ID", None))
AWS_SECRET_ACCESS_KEY = getattr(settings,
                                "CHUNK_UPLOADER_AWS_SECRET_ACCESS_KEY",
                                getattr(settings, "AWS_SECRET_ACCESS_KEY", None))
AWS_STORAGE_BUCKET_NAME = check_required_setting(
    "AWS_STORAGE_BUCKET_NAME",
    "CHUNK_UPLOADER_AWS_STORAGE_BUCKET_NAME",
)
AWS_REGION = check_required_setting(
    "CHUNK_UPLOADER_AWS_REGION",
    "AWS_REGION",
)
AWS_S3_ENDPOINT_URL = getattr(settings, "AWS_S3_ENDPOINT_URL", None)
S3_ROOT_DIRECTORY = getattr(settings, "CHUNK_UPLOADER_S3_ROOT_DIRECTORY", "")

S3_MIN_PART_SIZE = 5 * 1024 * 1024

CHUNK_UPLOADER_RAISE_EXCEPTION_ON_VIRUS_FOUND = getattr(
    settings, "CHUNK_UPLOADER_RAISE_EXCEPTION_ON_VIRUS_FOUND",
    False,
)

if (
    (getattr(settings, "DEFAULT_FILE_STORAGE", None) is None)
    or settings.DEFAULT_FILE_STORAGE  # noqa W504
    != "storages.backends.s3boto3.S3Boto3Storage"  # noqa W503
):
    logger.warning(
        "It is strongly recommended that you use S3Boto3Storage "
        "or a class that inherits from it with this file handler"
    )

if S3_ROOT_DIRECTORY and not S3_ROOT_DIRECTORY.endswith("/"):
    S3_ROOT_DIRECTORY = f"{S3_ROOT_DIRECTORY}/"


class ThreadedS3ChunkUploader(ThreadPoolExecutor):
    def __init__(self, client, bucket, key, upload_id, max_workers=None):
        max_workers = max_workers or 10
        self.bucket = bucket
        self.key = key
        self.upload_id = upload_id
        self.client = client
        self.part_number = 0
        self.parts = []
        self.queue = []
        self.current_queue_size = 0
        self.futures = []
        super().__init__(max_workers=max_workers)

    def add(self, body):
        if body:
            content_length = len(body)
            self.queue.append(body)
            self.current_queue_size += content_length

        if not body or self.current_queue_size > S3_MIN_PART_SIZE:
            self.part_number += 1
            _body = self.drain_queue()
            future = self.submit(
                self.client.upload_part,
                Bucket=self.bucket,
                Key=self.key,
                PartNumber=self.part_number,
                UploadId=self.upload_id,
                Body=_body,
                ContentLength=len(_body),
            )
            self.futures.append(future)
            self.parts.append((self.part_number, future))
            logger.debug("Prepared part %s", self.part_number)

    def drain_queue(self):
        body = b"".join(self.queue)
        self.queue = []
        self.current_queue_size = 0
        return body

    def get_parts(self):
        return [
            {
                "PartNumber": part[0],
                "ETag": part[1].result()["ETag"],
            }
            for part in self.parts
        ]


class S3FileUploadHandler(FileUploadHandler):
    def new_file(self, *args, **kwargs):
        super().new_file(*args, **kwargs)
        extension = pathlib.Path(self.file_name).suffix
        time_stamp = f'{timezone.now().strftime("%Y%m%d%H%M%S")}'
        self.new_file_name = f"{S3_ROOT_DIRECTORY}{self.file_name.replace(extension, '')}_{time_stamp}{extension}"

        extra_kwargs = {}
        if AWS_S3_ENDPOINT_URL:
            extra_kwargs['endpoint_url'] = AWS_S3_ENDPOINT_URL

        if AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY:
            extra_kwargs['aws_access_key_id'] = AWS_ACCESS_KEY_ID
            extra_kwargs['aws_secret_access_key'] = AWS_SECRET_ACCESS_KEY

        self.s3_client = boto3_client(
            "s3",
            region_name=AWS_REGION,
            **extra_kwargs,
        )

        self.parts = []
        self.part_number = 1
        self.s3_key = f"chunk_upload_{str(uuid.uuid4())}"

        self.multipart = self.s3_client.create_multipart_upload(
            Bucket=AWS_STORAGE_BUCKET_NAME,
            Key=self.s3_key,
            ContentType=self.content_type,
        )

        self.upload_id = self.multipart["UploadId"]
        self.executor = ThreadedS3ChunkUploader(
            self.s3_client,
            AWS_STORAGE_BUCKET_NAME,
            key=self.s3_key,
            upload_id=self.upload_id,
        )

    def receive_data_chunk(self, raw_data, start):
        try:
            self.executor.add(raw_data)
        except Exception as exc:
            logger.error("Aborting S3 upload", exc_info=exc)
            self.abort()

        return raw_data

    def file_complete(self, file_size):
        self.executor.add(None)

        # Wait for all threads to complete
        wait(
            self.executor.futures, return_when=concurrent.futures.ALL_COMPLETED
        )

        parts = self.executor.get_parts()

        self.s3_client.complete_multipart_upload(
            Bucket=AWS_STORAGE_BUCKET_NAME,
            Key=self.s3_key,
            UploadId=self.upload_id,
            MultipartUpload={"Parts": parts},
        )

        self.s3_client.copy_object(
            Bucket=AWS_STORAGE_BUCKET_NAME,
            CopySource=f"{AWS_STORAGE_BUCKET_NAME}/{self.s3_key}",
            Key=self.new_file_name,
            ContentType=self.content_type,
        )

        self.s3_client.delete_object(
            Bucket=AWS_STORAGE_BUCKET_NAME,
            Key=self.s3_key,
        )

        if "clam_av_results" in self.content_type_extra:
            for result in self.content_type_extra["clam_av_results"]:
                if result["file_name"] == self.file_name:
                    # Set AV headers
                    if result["av_passed"]:
                        self.s3_client.copy_object(
                            Bucket=AWS_STORAGE_BUCKET_NAME,
                            CopySource=f"{AWS_STORAGE_BUCKET_NAME}/{self.new_file_name}",
                            Key=self.new_file_name,
                            Metadata={
                                "av-scanned-at": result["scanned_at"].strftime(
                                    "%Y-%m-%d %H:%M:%S"
                                ),
                                "av-passed": "True",
                            },
                            ContentType=self.content_type,
                            MetadataDirective="REPLACE",
                        )
                    else:
                        # Remove file with virus from S3
                        self.s3_client.delete_object(
                            Bucket=AWS_STORAGE_BUCKET_NAME,
                            Key=self.new_file_name,
                        )

                        if CHUNK_UPLOADER_RAISE_EXCEPTION_ON_VIRUS_FOUND:
                            raise VirusFoundInFileException()
                        else:
                            return FileWithVirus(field_name=self.field_name)

        storage = S3Boto3Storage()
        file = S3Boto3StorageFile(self.new_file_name, "rb", storage)
        file.content_type = self.content_type
        file.original_name = self.file_name

        file.file_size = file_size
        file.close()

        return file

    def abort(self):
        self.s3_client.abort_multipart_upload(
            Bucket=AWS_STORAGE_BUCKET_NAME,
            Key=self.s3_key,
            UploadId=self.upload_id,
        )
