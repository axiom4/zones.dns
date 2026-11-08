from django.db import models


class Zone(models.Model):
    name = models.CharField(max_length=253, unique=True)  # lowercase, no trailing dot
    enabled = models.BooleanField(default=True)  # a disabled zone and its records are kept but not served: its names go on as if it did not exist

    def __str__(self):
        return self.name
