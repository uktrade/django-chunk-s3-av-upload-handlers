from django.db import models


class ScannedFile(models.Model):
    scanned_at = models.DateTimeField(auto_now_add=True)
    file_name = models.CharField(max_length=255)
    av_passed = models.BooleanField(default=False)
    av_reason = models.CharField(
        max_length=255,
        blank=True,
        null=True,
    )
