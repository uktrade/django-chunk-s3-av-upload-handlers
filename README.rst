================================
Django chunk S3 AV file uploader 
================================

This library provides two Django file upload handlers. 

The first of these, ``s3`` provides chunk uploading to an AWS S3 bucket and is heavily based on 
`<https://pypi.org/project/s3chunkuploader/>`_

The second provides chunk uploading to a ClamAV rest endpoint provided by - `<https://github.com/uktrade/dit-clamav-rest/>`_ although it could be used with other compatibile projects.

If used together, the results of the anti virus check are written to the object uploaded to S3.

Installation
------------

.. code-block:: python

    pip install django-chunk-s3-av-file-upload-handlers

Usage
-----

Using in a Django logging configuration:

.. code-block:: python

    INSTALLED_APPS = [
        ...
        "django_chunk_upload_handlers",
    ]

    FILE_UPLOAD_HANDLERS = (
        "django_chunk_upload_handlers.clam_av.ClamAVFileUploadHandler",
        "django_chunk_upload_handlers.s3.S3FileUploadHandler",
    )  # Order is important

Dependencies
------------

This project is a Django app and depends on the Django package. 

The ``s3`` file handler depends on  `boto3 <https://github.com/boto/boto3/>`_ and `django-storages <https://github.com/jschneier/django-storages/>`_ 

``settings.DEFAULT_FILE_STORAGE`` must be set to ``"storages.backends.s3boto3.S3Boto3Storage"`` or a class that derives from it.

Settings
--------

S3
***

:code:`AWS_ACCESS_KEY_ID`
:code:`CHUNK_UPLOADER_AWS_ACCESS_KEY_ID`

Provide either for the AWS access key required. ``CHUNK_UPLOADER_AWS_ACCESS_KEY_ID`` is preferred if both are set.

:code:`AWS_SECRET_ACCESS_KEY`
:code:`CHUNK_UPLOADER_AWS_SECRET_ACCESS_KEY`

Provide either for the AWS access secret key required. ``CHUNK_UPLOADER_AWS_SECRET_ACCESS_KEY`` is preferred if both are set.

:code:`AWS_STORAGE_BUCKET_NAME`
:code:`CHUNK_UPLOADER_AWS_STORAGE_BUCKET_NAME`

The S3 bucket to use for uploads. ``CHUNK_UPLOADER_AWS_STORAGE_BUCKET_NAME`` is preferred if both are set.

:code:`AWS_REGION`
:code:`CHUNK_UPLOADER_AWS_REGION`

The AWS region to use. ``CHUNK_UPLOADER_AWS_REGION`` is preferred if both are set.

:code:`S3_ROOT_DIRECTORY`
:code:`CHUNK_UPLOADER_S3_ROOT_DIRECTORY`

The directory path to use as root for uploads. ``CHUNK_UPLOADER_S3_ROOT_DIRECTORY`` is preferred if both are set.

:code:`ADD_TIMESTAMP_TO_OBJECT_NAME`
Adds a timestamp to uploaded object's file name if set. Defaults to ``True``.

ClamAV
******

:code:`CLAM_AV_USERNAME`
The ClamAV service username.

:code:`CLAM_AV_PASSWORD`
The ClamAV service password.

:code:`CLAM_AV_DOMAIN`
The domain to use for the ClamAV service. Note, this is domain only so ``test.com`` rather than ``https://test.com``

:code:`CLAM_PATH`
The path to the ClamAV service (used with the domain defined in the setting above). Defaults to ``/v2/scan-chunked``

:code:`CLAM_AV_IGNORE_EXTENSIONS`
A list of file extensions to not process with ClamAV. Defaults to an empty list.

:code:`CLAM_USE_HTTP`
Use http rather than https. Should not be used in production environments. Defaults to ``False``.

Tests
-----

.. code-block:: console

    $ pip install -r requirements.txt
    $ tox
