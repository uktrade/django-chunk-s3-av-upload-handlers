import json
import logging
import pathlib
from base64 import b64encode
from http.client import HTTPConnection, HTTPSConnection

# Check that HTTPSConnection is secure in the version of Python you are using
# https://wiki.openstack.org/wiki/OSSN/OSSN-0033

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import UploadedFile
from django.core.files.uploadhandler import (
    FileUploadHandler,
    UploadFileException,
)
from django.utils.translation import gettext_lazy as _

from django_chunk_upload_handlers.models import ScannedFile
from django_chunk_upload_handlers.util import check_required_setting


logger = logging.getLogger(__name__)


CHUNK_SIZE = 5 * 1024 * 1024

# Clam AV
CLAM_AV_USERNAME = check_required_setting("CLAM_AV_USERNAME")
CLAM_AV_PASSWORD = check_required_setting("CLAM_AV_PASSWORD")
CLAM_AV_DOMAIN = check_required_setting("CLAM_AV_DOMAIN")
CLAM_PATH = getattr(settings, "CLAM_PATH", "/v2/scan-chunked")
CLAM_AV_IGNORE_EXTENSIONS = getattr(settings, "CLAM_AV_IGNORE_EXTENSIONS", {})
CLAM_USE_HTTP = getattr(settings, "CLAM_USE_HTTP", False)  # Do not use in production!


class VirusFoundInFileException(UploadFileException):
    pass


def validate_virus_check_result(file):
    try:
        file.readline()
    except VirusFoundInFileException:
        raise ValidationError(
            _('A virus was found'),
        )


class FileWithVirus(UploadedFile):
    def __init__(self, field_name):
        super().__init__(file="virus", name="virus", size="virus")
        self.field_name = field_name

    def open(self, mode=None):
        raise VirusFoundInFileException(
            "Cannot open file - virus was found",
        )

    def chunks(self, chunk_size=None):
        raise VirusFoundInFileException(
            "Cannot read file chunks - virus was found",
        )

    def multiple_chunks(self, chunk_size=None):
        raise VirusFoundInFileException(
            "Cannot read file chunks - virus was found",
        )

    def readline(self):
        raise VirusFoundInFileException(
            "Cannot read line - virus was found",
        )


class AntiVirusServiceErrorException(UploadFileException):
    pass


class MalformedAntiVirusResponseException(UploadFileException):
    pass


class ClamAVFileUploadHandler(FileUploadHandler):
    chunk_size = CHUNK_SIZE
    skip_av_check = False

    def new_file(self, *args, **kwargs):
        super().new_file(*args, **kwargs)
        extension = pathlib.Path(self.file_name).suffix

        if extension in CLAM_AV_IGNORE_EXTENSIONS:
            self.skip_av_check = True
            return

        if CLAM_USE_HTTP:
            self.av_conn = HTTPConnection(
                host=CLAM_AV_DOMAIN,
            )
        else:
            self.av_conn = HTTPSConnection(  # noqa S309
                host=CLAM_AV_DOMAIN,
                port=443,
            )

        credentials = b64encode(
            bytes(
                f"{CLAM_AV_USERNAME}:{CLAM_AV_PASSWORD}",
                encoding="utf8",
            )
        ).decode("ascii")

        try:
            self.av_conn.connect()
            self.av_conn.putrequest("POST", CLAM_PATH)
            self.av_conn.putheader("Content-Type", self.content_type)
            self.av_conn.putheader("Authorization", f"Basic {credentials}")
            self.av_conn.putheader("Transfer-encoding", "chunked")
            self.av_conn.endheaders()
        except Exception as ex:
            logger.error("Error connecting to ClamAV service", exc_info=True)
            raise AntiVirusServiceErrorException(ex)

    def receive_data_chunk(self, raw_data, start):
        if not self.skip_av_check:
            self.av_conn.send(hex(len(raw_data))[2:].encode("utf-8"))
            self.av_conn.send(b"\r\n")
            self.av_conn.send(raw_data)
            self.av_conn.send(b"\r\n")

        return raw_data

    def file_complete(self, file_size):
        if self.skip_av_check:
            return None

        self.av_conn.send(b"0\r\n\r\n")

        resp = self.av_conn.getresponse()
        response_content = resp.read()

        scanned_file = ScannedFile()

        if resp.status != 200:
            scanned_file.av_passed = False
            scanned_file.av_reason = "Non 200 response from AV server"
            scanned_file.save()

            raise AntiVirusServiceErrorException(
                f"Non 200 response from anti virus service, content: {response_content}"
            )
        else:
            json_response = json.loads(response_content)

            if "malware" not in json_response:
                scanned_file.av_passed = False
                scanned_file.av_reason = "Malformed response from AV server"
                scanned_file.save()

                raise MalformedAntiVirusResponseException()

            if json_response["malware"]:
                scanned_file.av_passed = False
                scanned_file.av_reason = json_response["reason"]
                scanned_file.save()
                logger.error(
                    f"Malware found in user uploaded file "
                    f"'{self.file_name}', exiting upload process"
                )
            else:
                scanned_file.av_passed = True
                scanned_file.save()

            # We are using 'content_type_extra' as the a means of making
            # the results available to following file handlers

            #  TODO - put in a PR to Django project to allow file_complete
            # to return objects and not break out of file handler loop
            if not hasattr(self.content_type_extra, "clam_av_results"):
                self.content_type_extra["clam_av_results"] = []

            self.content_type_extra["clam_av_results"].append(
                {
                    "file_name": self.file_name,
                    "av_passed": scanned_file.av_passed,
                    "scanned_at": scanned_file.scanned_at,
                }
            )

            return None
