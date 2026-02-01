from rest_framework import serializers
from .models import NetworkAlert, NetworkStatistic


class MonitorConfigSerializer(serializers.Serializer):
    interface = serializers.CharField(default="eth0")
    packet_limit = serializers.IntegerField(default=1000)


class MonitorStatusSerializer(serializers.Serializer):
    is_monitoring = serializers.BooleanField()
    interface = serializers.CharField()
    total_packets = serializers.IntegerField()
    total_bytes = serializers.IntegerField()
    bandwidth_mbps = serializers.FloatField()
    packet_types = serializers.DictField()
    alerts_count = serializers.IntegerField()
    uptime_seconds = serializers.FloatField()
    start_time = serializers.DateTimeField(allow_null=True, required=False)


class NetworkAlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetworkAlert
        fields = '__all__'
        read_only_fields = ['timestamp']


class NetworkStatisticSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetworkStatistic
        fields = '__all__'
        read_only_fields = ['timestamp']


class NetworkInterfaceSerializer(serializers.Serializer):
    name = serializers.CharField()
    ipv4 = serializers.ListField(child=serializers.DictField(), required=False)
    ipv6 = serializers.ListField(child=serializers.DictField(), required=False)
    mac = serializers.CharField(allow_null=True)
    is_up = serializers.BooleanField()
    speed_mbps = serializers.IntegerField(allow_null=True)


class ElevationTokenSerializer(serializers.Serializer):
    token = serializers.CharField()


class PrivilegeStatusSerializer(serializers.Serializer):
    has_privileges = serializers.BooleanField()
    is_admin = serializers.BooleanField()
    user_role = serializers.CharField()
    requires_elevation = serializers.BooleanField()
    instructions = serializers.CharField()


class ElevationMethodSerializer(serializers.Serializer):
    id = serializers.CharField()
    name = serializers.CharField()
    description = serializers.CharField()
    requires_password = serializers.BooleanField()
    gui_supported = serializers.BooleanField()
