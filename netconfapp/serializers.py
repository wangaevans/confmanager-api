from rest_framework import serializers
from .models import Device, Configuration, Log

class ConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Configuration
        fields = '__all__'

class LogSerializer(serializers.ModelSerializer):
    class Meta:
        model = Log
        fields = '__all__'

class DeviceSerializer(serializers.ModelSerializer):
    configurations = ConfigurationSerializer(many=True, read_only=True)
    
    class Meta:
        model = Device
        fields = '__all__'
