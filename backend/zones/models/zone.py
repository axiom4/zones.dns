from django.db import models


class Zone(models.Model):
    name = models.CharField(max_length=253, unique=True)  # lowercase, no trailing dot

    def __str__(self):
        return self.name
