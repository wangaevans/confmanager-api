# models.py

from django.contrib.auth.models import User
from django.db import models
from django.contrib.auth.models import User
import uuid


class Device(models.Model):
    id=models.UUIDField(primary_key=True,default=uuid.uuid4(),editable=False,unique=False)
    ip = models.CharField(max_length=100)
    username = models.CharField(max_length=100)
    password = models.CharField(max_length=100)
    vendor = models.CharField(max_length=100)
    port = models.IntegerField(default=22)
    default_configuration_version = models.ForeignKey(
        'Configuration', on_delete=models.SET_NULL, null=True, blank=True, related_name='default_for_device')
    def __str__(self):
        return self.username

    def get_configurations(self):
        return self.configurations.all().order_by('-timestamp')


class Configuration(models.Model):
    id = models.UUIDField(
        primary_key=True, default=uuid.uuid4(), editable=False)
    device = models.ForeignKey(
        Device, related_name='configurations', on_delete=models.CASCADE)
    configuration = models.TextField()
    version_tag = models.CharField(max_length=50)
    timestamp = models.DateTimeField()
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # Add user field
    diff = models.TextField(blank=True)  #
    updated_config = models.TextField(blank=True)
    models.FileField(upload_to='config_files', blank=True)


class Log(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=100)
    success = models.BooleanField(default=False)
    details = models.TextField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user} - {self.action} {'(Success)' if self.success else '(Failure)'} at {self.timestamp}"
