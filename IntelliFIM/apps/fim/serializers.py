from rest_framework import serializers
from .models import Directory, FileMetadata

class FIMStartRequestSerializer(serializers.Serializer):
    directories = serializers.ListField(
        child=serializers.CharField(max_length=500),
        min_length=1
    )
    excluded_files = serializers.ListField(
        child=serializers.CharField(max_length=500),
        required=False,
        default=[]
    )

    def validate_directories(self, value):
        import os
        for directory in value:
            if not os.path.exists(directory):
                raise serializers.ValidationError(f"Directory does not exist: {directory}")
        return value

class FIMStopRequestSerializer(serializers.Serializer):
    directories = serializers.ListField(
        child=serializers.CharField(max_length=500),
        min_length=1
    )

class FIMAddPathRequestSerializer(serializers.Serializer):
    directory = serializers.CharField(max_length=500)

    def validate_directory(self, value):
        import os
        if not os.path.exists(value):
            raise serializers.ValidationError(f"Directory does not exist: {value}")
        return value

class FIMRestoreRequestSerializer(serializers.Serializer):
    path_to_restore = serializers.CharField(max_length=500)

class FIMStatusResponseSerializer(serializers.Serializer):
    is_monitoring = serializers.BooleanField()
    watched_directories = serializers.ListField(child=serializers.CharField())
    total_watched = serializers.IntegerField()

class FileChangeSerializer(serializers.Serializer):
    hash = serializers.CharField()
    last_modified = serializers.CharField(required=False, allow_null=True)
    type = serializers.CharField(required=False)
    detected_at = serializers.CharField(required=False, allow_null=True)

class FIMChangesResponseSerializer(serializers.Serializer):
    added = serializers.DictField(child=FileChangeSerializer())
    modified = serializers.DictField(child=FileChangeSerializer())
    deleted = serializers.DictField(child=FileChangeSerializer())
    total_changes = serializers.IntegerField()

class FIMLogsResponseSerializer(serializers.Serializer):
    directory = serializers.CharField()
    log_file = serializers.CharField()
    content = serializers.CharField()

class DirectorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Directory
        fields = ('id', 'path', 'created_at')
        read_only_fields = ('id', 'created_at')

class FileMetadataSerializer(serializers.ModelSerializer):
    directory_path = serializers.CharField(source='directory.path', read_only=True)

    class Meta:
        model = FileMetadata
        fields = ('id', 'directory', 'directory_path', 'item_path', 'item_type', 
                 'hash', 'last_modified', 'status', 'detected_at')
        read_only_fields = ('id', 'detected_at')

class BaselineItemSerializer(serializers.Serializer):
    type = serializers.CharField()
    hash = serializers.CharField()
    last_modified = serializers.CharField(allow_null=True)
    detected_at = serializers.CharField(allow_null=True)

class BaselineResponseSerializer(serializers.Serializer):
    baseline = serializers.DictField(child=serializers.DictField(child=BaselineItemSerializer()))
    total_items = serializers.IntegerField()
