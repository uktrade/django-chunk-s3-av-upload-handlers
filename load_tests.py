import sys
from unittest import TestSuite
from django.test.runner import DiscoverRunner

import os
import django
from django.conf import settings

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "django_chunk_upload_handlers"))

settings.configure(
    BASE_DIR=BASE_DIR,
    DEBUG=True,
    DATABASES={
        "default":{
            "ENGINE":"django.db.backends.sqlite3",
            "NAME": os.path.join(BASE_DIR, "db.sqlite3"),
        }
    },
    INSTALLED_APPS=(
        "django_chunk_upload_handlers",
    ),
    TIME_ZONE="UTC",
    USE_TZ=True,
    # Required django_chunk_upload_handlers app settings
    # See django_chunk_upload_handlers/util.py (causes load_tests.py to error if not defined)
    CLAM_AV_USERNAME="",
    CLAM_AV_PASSWORD="",
    CLAM_AV_DOMAIN="",
    AWS_ACCESS_KEY_ID="",
    AWS_SECRET_ACCESS_KEY="",
    AWS_STORAGE_BUCKET_NAME="",
    CHUNK_UPLOADER_AWS_REGION="",
)

django.setup()

default_labels = ["django_chunk_upload_handlers.test", ]


def get_suite(labels=None):
    if labels is None:
        labels = default_labels

    runner = DiscoverRunner(verbosity=1)
    failures = runner.run_tests(labels)
    if failures:
        sys.exit(failures)

    return TestSuite()


if __name__ == "__main__":
    _labels = default_labels

    if len(sys.argv[1:]) > 0:
        _labels = sys.argv[1:]

    get_suite(_labels)
