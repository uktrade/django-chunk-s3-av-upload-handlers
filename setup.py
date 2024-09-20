from distutils.core import setup

import setuptools


with open("README.rst", "r") as fh:
    long_description = fh.read()

setup(
    name="django_chunk_upload_handlers",
    version="0.0.15",
    packages=setuptools.find_packages(),
    author="Ross Miller",
    author_email="ross.miller@digital.trade.gov.uk",
    url="https://github.com/uktrade/django-chunk-s3-av-upload-handlers",
    description="Chunking Django file handlers for S3 and ClamAV service uploads",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    install_requires=[
        "django>=4.2,<6.0",
        "boto3>=1.17.89",
        "django-storages>=1.11.1",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)
