import concurrent.futures
from datetime import datetime
from unittest.mock import MagicMock, call, patch

from django.test import TestCase
from django.test.client import RequestFactory

from django_chunk_upload_handlers.s3 import (
    S3FileUploadHandler,
    ThreadedS3ChunkUploader,
)

from django_chunk_upload_handlers.clam_av import FileWithVirus, VirusFoundInFileException


class S3FileHandlerTestCase(TestCase):
    def setUp(self):
        self.request_factory = RequestFactory()
        self.request = self.request_factory.request()

    def create_s3_handler(self):
        self.s3_file_handler = S3FileUploadHandler(
            request=self.request,
        )
        self.s3_file_handler.new_file(
            "file",
            "file.txt",
            "text/plain",
            100,
            content_type_extra=None,
        )

    @patch("django_chunk_upload_handlers.s3.boto3_client")
    @patch("django_chunk_upload_handlers.s3.ThreadedS3ChunkUploader")
    def test_init_connection_without_environment(self, thread_pool, boto3_client):
        self.s3_file_handler = S3FileUploadHandler(request=self.request)
        self.s3_file_handler.new_file(
            "file",
            "file.txt",
            "text/plain",
            100,
            content_type_extra=None,
        )

        self.s3_file_handler.s3_client.create_multipart_upload.assert_called_once()
        boto3_client.assert_called_with("s3", region_name="")

        thread_pool.assert_called_once()

    @patch("django_chunk_upload_handlers.s3.boto3_client")
    @patch("django_chunk_upload_handlers.s3.ThreadedS3ChunkUploader")
    @patch("django_chunk_upload_handlers.s3.AWS_ACCESS_KEY_ID", 'access-key')
    @patch("django_chunk_upload_handlers.s3.AWS_SECRET_ACCESS_KEY", 'secret-key')
    def test_init_connection_with_environment(self, thread_pool, boto3_client):
        self.s3_file_handler = S3FileUploadHandler(request=self.request)
        self.s3_file_handler.new_file(
            "file",
            "file.txt",
            "text/plain",
            100,
            content_type_extra=None,
        )

        self.s3_file_handler.s3_client.create_multipart_upload.assert_called_once()
        boto3_client.assert_called_with("s3",
                                        region_name="",
                                        aws_access_key_id='access-key',
                                        aws_secret_access_key='secret-key')

        thread_pool.assert_called_once()

    @patch("django_chunk_upload_handlers.s3.boto3_client")
    def test_chunk_is_received(self, client):
        self.create_s3_handler()
        self.s3_file_handler.executor = MagicMock()
        self.s3_file_handler.receive_data_chunk(
            b"test",
            0,
        )
        # Check that we started to send data
        self.s3_file_handler.executor.mock_calls[0] = call.send(b"4")

    @patch("django_chunk_upload_handlers.s3.boto3_client")
    @patch("django_chunk_upload_handlers.s3.S3Boto3Storage")
    @patch("django_chunk_upload_handlers.s3.S3Boto3StorageFile")
    def test_addition_of_av_header(self, storage_file, storage, client):
        self.create_s3_handler()

        # Add content_type_extra which would have been added by file handler processor
        self.s3_file_handler.content_type_extra = {"clam_av_results": []}
        self.s3_file_handler.content_type_extra["clam_av_results"].append(
            {"file_name": "file.txt", "av_passed": True, "scanned_at": datetime.now()}
        )

        self.s3_file_handler.s3_client.head_object = MagicMock()
        self.s3_file_handler.s3_client.head_object.return_value = {
            "ETag": "Test...",
        }

        self.s3_file_handler.file_complete(0)

        # copy_object should have been called twice,
        # the second time to add the AV metadata
        self.assertEqual(
            self.s3_file_handler.s3_client.copy_object.call_count,
            2,
        )

        second_copy_obj_call_list = (
            self.s3_file_handler.s3_client.copy_object.call_args_list[1][1]
        )

        self.assertTrue("Metadata" in second_copy_obj_call_list)
        self.assertTrue("av-passed" in second_copy_obj_call_list["Metadata"])
        self.assertTrue(second_copy_obj_call_list["Metadata"]["av-passed"])

    @patch("django_chunk_upload_handlers.s3.boto3_client")
    @patch("django_chunk_upload_handlers.s3.S3Boto3Storage")
    @patch("django_chunk_upload_handlers.s3.S3Boto3StorageFile")
    @patch("django_chunk_upload_handlers.s3.CHUNK_UPLOADER_RAISE_EXCEPTION_ON_VIRUS_FOUND", True)
    def test_virus_found_with_raise_exception_setting(self, storage_file, storage, client):
        self.create_s3_handler()

        # Add content_type_extra which would have been added by file handler processor
        self.s3_file_handler.content_type_extra = {"clam_av_results": []}
        self.s3_file_handler.content_type_extra["clam_av_results"].append(
            {"file_name": "file.txt", "av_passed": False, "scanned_at": datetime.now()}
        )

        with self.assertRaises(VirusFoundInFileException):
            self.s3_file_handler.file_complete(0)

    @patch("django_chunk_upload_handlers.s3.boto3_client")
    @patch("django_chunk_upload_handlers.s3.S3Boto3Storage")
    @patch("django_chunk_upload_handlers.s3.S3Boto3StorageFile")
    def test_virus_found_without_raise_exception_setting(self, storage_file, storage, client):
        self.create_s3_handler()

        # Add content_type_extra which would have been added by file handler processor
        self.s3_file_handler.content_type_extra = {"clam_av_results": []}
        self.s3_file_handler.content_type_extra["clam_av_results"].append(
            {"file_name": "file.txt", "av_passed": False, "scanned_at": datetime.now()}
        )

        outcome = self.s3_file_handler.file_complete(0)
        self.assertEqual(type(outcome).__name__, "FileWithVirus")

class ThreadedS3ChunkUploaderTestCase(TestCase):
    @patch("django_chunk_upload_handlers.s3.S3_MIN_PART_SIZE", 10)
    @patch("django_chunk_upload_handlers.s3.boto3_client")
    def test_add_future_with_body(self, client):
        test_etag = "test"
        client.upload_part.return_value = {"ETag": test_etag}

        threaded_s3_uploader = ThreadedS3ChunkUploader(
            client, "test_bucket", "test_key", "test_upload_id"
        )

        threaded_s3_uploader.add(b"ninebytes")
        self.assertEqual(threaded_s3_uploader.current_queue_size, 9)

        threaded_s3_uploader.client.upload_part.assert_not_called()

        # Push total bytes above min size
        threaded_s3_uploader.add(b"morebytes")
        self.assertEqual(threaded_s3_uploader.current_queue_size, 0)
        self.assertEqual(len(threaded_s3_uploader.futures), 1)

        # Wait for upload threads to complete
        concurrent.futures.wait(
            threaded_s3_uploader.futures, return_when=concurrent.futures.ALL_COMPLETED
        )

        # There should have only been one upload call
        threaded_s3_uploader.client.upload_part.assert_called_once()

        # Check parts is as expected
        parts = threaded_s3_uploader.get_parts()

        self.assertEqual(len(parts), 1)
        self.assertEqual(parts[0]["PartNumber"], 1)
        self.assertEqual(parts[0]["ETag"], test_etag)

    @patch("django_chunk_upload_handlers.s3.S3Boto3StorageFile")
    @patch("django_chunk_upload_handlers.s3.wait")
    @patch("django_chunk_upload_handlers.s3.boto3_client")
    def test_original_file_name_available(self, client, wait, storage):
        threaded_s3_uploader = S3FileUploadHandler()
        threaded_s3_uploader.executor = MagicMock()
        threaded_s3_uploader.s3_client = MagicMock()
        threaded_s3_uploader.s3_key = "test"
        threaded_s3_uploader.upload_id = "test"
        threaded_s3_uploader.content_type_extra = {}

        threaded_s3_uploader.file_name = "filename.jpg"
        threaded_s3_uploader.new_file_name = "newfilename.jpg"

        test_file = threaded_s3_uploader.file_complete(file_size=1)
        self.assertEqual(test_file.original_name, "filename.jpg")
