# Generated by Django 5.0.1 on 2024-03-19 15:30

import django.db.models.deletion
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Configuration',
            fields=[
                ('id', models.UUIDField(default=uuid.UUID('1ce999cb-3483-4954-a679-170e97c79eca'), editable=False, primary_key=True, serialize=False)),
                ('configuration', models.TextField()),
                ('version_tag', models.CharField(max_length=50)),
                ('timestamp', models.DateTimeField()),
                ('diff', models.TextField(blank=True)),
                ('updated_config', models.TextField(blank=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Device',
            fields=[
                ('id', models.UUIDField(default=uuid.UUID('3b61da8f-cf49-43e3-b48b-ff58c7c50eee'), editable=False, primary_key=True, serialize=False)),
                ('ip', models.CharField(max_length=100)),
                ('username', models.CharField(max_length=100)),
                ('password', models.CharField(max_length=100)),
                ('vendor', models.CharField(max_length=100)),
                ('port', models.IntegerField(default=22)),
                ('default_configuration_version', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='default_for_device', to='netconfapp.configuration')),
            ],
        ),
        migrations.AddField(
            model_name='configuration',
            name='device',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='configurations', to='netconfapp.device'),
        ),
        migrations.CreateModel(
            name='Log',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('action', models.CharField(max_length=100)),
                ('success', models.BooleanField(default=False)),
                ('details', models.TextField(blank=True, null=True)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]