from unittest.mock import MagicMock, Mock, call, patch

from django.test import TestCase
from django.test.client import RequestFactory

from django_chunk_upload_handlers.clam_av import (
    AntiVirusServiceErrorException,
    ClamAVFileUploadHandler,
    MalformedAntiVirusResponseException,
    VirusFoundInFileException,
)
from django_chunk_upload_handlers.models import ScannedFile

test_clam_av_domain = "test.com"


# Need to directly override settings rather than using
# override_settings as it does not work with logic used
class ClamAVFileHandlerTestCase(TestCase):
    def setUp(self):
        self.request_factory = RequestFactory()
        self.request = self.request_factory.request()

    @patch("django_chunk_upload_handlers.clam_av.CLAM_AV_DOMAIN", test_clam_av_domain)
    def create_av_handler(self):
        self.clam_av_file_handler = ClamAVFileUploadHandler(
            request=self.request,
        )
        self.clam_av_file_handler.new_file(
            "file",
            "file.txt",
            "text/plain",
            100,
        )
        setattr(self.clam_av_file_handler, 'content_type_extra', {})

    @patch("django_chunk_upload_handlers.clam_av.HTTPSConnection")
    def test_init_connection(self, http_connection):
        self.create_av_handler()

        # Check that we made a connection
        http_connection.mock_calls[0] = call(test_clam_av_domain)

    @patch("django_chunk_upload_handlers.clam_av.HTTPSConnection")
    def test_chunk_is_received(self, http_connection):
        self.create_av_handler()
        self.clam_av_file_handler.av_conn = MagicMock()
        self.clam_av_file_handler.receive_data_chunk(
            b"test",
            0,
        )
        # Check that we started to send data
        self.clam_av_file_handler.av_conn.mock_calls[0] = call.send(b"4")

    @patch(
        "django_chunk_upload_handlers.clam_av.CLAM_AV_IGNORE_EXTENSIONS",
        {
            ".txt",
        },
    )
    @patch("django_chunk_upload_handlers.clam_av.HTTPConnection")
    def test_no_connection_if_ext_exempt(self, http_connection):
        self.create_av_handler()

        # Check that we did not make a connection
        self.assertEqual(len(http_connection.mock_calls), 0)

    @patch(
        "django_chunk_upload_handlers.clam_av.CLAM_AV_IGNORE_EXTENSIONS",
        {
            ".txt",
        },
    )
    @patch("django_chunk_upload_handlers.clam_av.HTTPConnection")
    def test_no_chunk_processing_if_ext_exempt(self, http_connection):
        self.create_av_handler()
        self.clam_av_file_handler.av_conn = MagicMock()
        self.clam_av_file_handler.receive_data_chunk(
            b"test",
            0,
        )

        # Check that we did not process chunk
        self.assertEqual(len(self.clam_av_file_handler.av_conn.mock_calls), 0)

    @patch(
        "django_chunk_upload_handlers.clam_av.CLAM_AV_IGNORE_EXTENSIONS",
        {
            ".txt",
        },
    )
    @patch("django_chunk_upload_handlers.clam_av.HTTPConnection")
    def test_no_virus_check_ext_exempt(self, http_connection):
        self.create_av_handler()
        self.clam_av_file_handler.av_conn = MagicMock()
        self.clam_av_file_handler.file_complete(0)

        # Check that we did send to AV
        self.assertEqual(len(self.clam_av_file_handler.av_conn.mock_calls), 0)

    @patch("django_chunk_upload_handlers.clam_av.HTTPSConnection")
    def test_file_complete_with_non_200_response_from_av_service(
        self, _http_connection
    ):
        self.create_av_handler()

        self.clam_av_file_handler.av_conn.getresponse.return_value = Mock(
            status=403,
        )

        with self.assertRaises(AntiVirusServiceErrorException):
            self.clam_av_file_handler.file_complete(0)

        self.assertEqual(ScannedFile.objects.count(), 1)
        self.assertFalse(ScannedFile.objects.first().av_passed)

    @patch("django_chunk_upload_handlers.clam_av.HTTPSConnection")
    def test_file_complete_malformed_av_response(self, _http_connection):
        self.create_av_handler()

        self.clam_av_file_handler.av_conn.getresponse.return_value = Mock(
            status=200, read=Mock(return_value='{ "malformed": false }')
        )

        with self.assertRaises(MalformedAntiVirusResponseException):
            self.clam_av_file_handler.file_complete(0)

        self.assertEqual(ScannedFile.objects.count(), 1)
        self.assertFalse(ScannedFile.objects.first().av_passed)

    @patch("django_chunk_upload_handlers.clam_av.HTTPSConnection")
    def test_file_complete_virus_found(self, _http_connection):
        self.create_av_handler()

        self.clam_av_file_handler.av_conn.getresponse.return_value = Mock(
            status=200, read=Mock(return_value='{ "malware": true, "reason": "test" }')
        )

        self.clam_av_file_handler.file_complete(0)

        self.assertFalse(
            self.clam_av_file_handler.content_type_extra["clam_av_results"][0]["av_passed"]
        )

        self.assertEqual(ScannedFile.objects.count(), 1)
        self.assertFalse(ScannedFile.objects.first().av_passed)

    @patch("django_chunk_upload_handlers.clam_av.HTTPSConnection")
    def test_file_complete_no_virus_found(self, _http_connection):
        self.create_av_handler()

        # Add content_type_extra which would have been added by file handler processor
        self.clam_av_file_handler.content_type_extra = {}

        self.clam_av_file_handler.av_conn.getresponse.return_value = Mock(
            status=200, read=Mock(return_value='{ "malware": false, "reason": "test" }')
        )

        self.clam_av_file_handler.file_complete(0)

        self.assertEqual(ScannedFile.objects.count(), 1)
        self.assertTrue(ScannedFile.objects.first().av_passed)

        self.assertTrue(
            self.clam_av_file_handler.content_type_extra["clam_av_results"][0][
                "av_passed"
            ]
        )
