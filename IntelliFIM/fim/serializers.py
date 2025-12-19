"""
fim/serializers.py
------------------
Django REST Framework serializers for FIM API
"""
from rest_framework import serializers
from django.core.validators import RegexValidator
from django.utils import timezone
from .models import (
    Directory, 
    FileMetadata, 
    FIMConfiguration,
    FIMLog,
    BackupRecord,
    ExclusionPattern
)


# ==================== Request Serializers ====================

class FIMStartRequestSerializer(serializers.Serializer):
    """Serializer for starting FIM monitoring"""
    directories = serializers.ListField(
        child=serializers.CharField(max_length=500),
        min_length=1,
        help_text="List of directories to monitor"
    )

    excluded_files = serializers.ListField(
        child=serializers.CharField(max_length=200),
        required=False,
        default=list,
        help_text="List of file patterns to exclude"
    )

    recursive = serializers.BooleanField(
        required=False,
        default=True,
        help_text="Monitor subdirectories recursively"
    )

    scan_interval = serializers.IntegerField(
        required=False,
        default=300,
        min_value=10,
        max_value=86400,
        help_text="Scan interval in seconds"
    )

    def validate_directories(self, value):
        """Validate that directories exist"""
        import os
        invalid_dirs = []
        for directory in value:
            if not os.path.exists(directory):
                invalid_dirs.append(directory)

        if invalid_dirs:
            raise serializers.ValidationError(
                f"Directories do not exist: {', '.join(invalid_dirs)}"
            )
        return value


class FIMStopRequestSerializer(serializers.Serializer):
    """Serializer for stopping FIM monitoring"""
    directories = serializers.ListField(
        child=serializers.CharField(max_length=500),
        min_length=1,
        help_text="List of directories to stop monitoring"
    )

    remove_from_db = serializers.BooleanField(
        required=False,
        default=False,
        help_text="Remove directories from database"
    )


class FIMAddPathRequestSerializer(serializers.Serializer):
    """Serializer for adding a directory to monitor"""
    directory = serializers.CharField(
        max_length=500,
        help_text="Directory path to add"
    )

    recursive = serializers.BooleanField(
        required=False,
        default=True,
        help_text="Monitor subdirectories recursively"
    )

    scan_interval = serializers.IntegerField(
        required=False,
        default=300,
        min_value=10,
        max_value=86400,
        help_text="Scan interval in seconds"
    )

    def validate_directory(self, value):
        """Validate that directory exists"""
        import os
        if not os.path.exists(value):
            raise serializers.ValidationError(f"Directory does not exist: {value}")
        return os.path.normpath(value)


class FIMRestoreRequestSerializer(serializers.Serializer):
    """Serializer for restoring files from backup"""
    path_to_restore = serializers.CharField(
        max_length=500,
        help_text="Path to restore"
    )

    backup_id = serializers.IntegerField(
        required=False,
        help_text="Specific backup ID to restore from"
    )

    restore_location = serializers.CharField(
        max_length=500,
        required=False,
        help_text="Alternative location to restore to"
    )

    overwrite = serializers.BooleanField(
        required=False,
        default=True,
        help_text="Overwrite existing files"
    )


class FIMResetBaselineRequestSerializer(serializers.Serializer):
    """Serializer for resetting baseline"""
    directories = serializers.ListField(
        child=serializers.CharField(max_length=500),
        min_length=1,
        help_text="List of directories to reset baseline for"
    )

    force = serializers.BooleanField(
        required=False,
        default=False,
        help_text="Force reset even if monitoring is active"
    )


class FIMScanRequestSerializer(serializers.Serializer):
    """Serializer for triggering manual scan"""
    directories = serializers.ListField(
        child=serializers.CharField(max_length=500),
        required=False,
        default=list,
        help_text="Specific directories to scan (empty for all)"
    )

    deep_scan = serializers.BooleanField(
        required=False,
        default=False,
        help_text="Perform deep hash calculation"
    )


# ==================== Response Serializers ====================

class DirectorySerializer(serializers.ModelSerializer):
    """Serializer for Directory model"""

    file_count = serializers.SerializerMethodField()
    last_change = serializers.SerializerMethodField()
    is_monitored = serializers.BooleanField(source='is_active', read_only=True)

    class Meta:
        model = Directory
        fields = [
            'id', 'path', 'created_at', 'is_active', 'last_scan',
            'recursive', 'scan_interval', 'file_count', 'last_change',
            'is_monitored'
        ]
        read_only_fields = ['id', 'created_at', 'file_count', 'last_change']

    def get_file_count(self, obj):
        """Get count of files in directory"""
        return obj.files.filter(status='current').count()

    def get_last_change(self, obj):
        """Get timestamp of last change in directory"""
        last_change = obj.files.exclude(status='current').order_by('-detected_at').first()
        return last_change.detected_at if last_change else None


class FileMetadataSerializer(serializers.ModelSerializer):
    """Serializer for FileMetadata model"""

    directory_path = serializers.CharField(source='directory.path', read_only=True)
    full_path = serializers.SerializerMethodField()
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    item_type_display = serializers.CharField(source='get_item_type_display', read_only=True)

    class Meta:
        model = FileMetadata
        fields = [
            'id', 'change_id', 'directory', 'directory_path',
            'item_path', 'full_path', 'item_type', 'item_type_display',
            'hash', 'previous_hash', 'size', 'permissions', 'owner', 'group',
            'last_modified', 'created_at', 'detected_at', 'status', 'status_display',
            'reported', 'restored'
        ]
        read_only_fields = [
            'id', 'change_id', 'created_at', 'detected_at', 
            'status_display', 'item_type_display', 'full_path'
        ]

    def get_full_path(self, obj):
        """Get full absolute path"""
        import os
        return os.path.join(obj.directory.path, obj.item_path)


class FIMStatusResponseSerializer(serializers.Serializer):
    """Serializer for FIM status response"""

    is_monitoring = serializers.BooleanField()
    watched_directories = serializers.ListField(child=serializers.CharField())
    active_directories = serializers.ListField(child=serializers.CharField())
    total_configured = serializers.IntegerField()
    total_active = serializers.IntegerField()

    # Additional status info
    last_scan_time = serializers.DateTimeField(required=False)
    next_scheduled_scan = serializers.DateTimeField(required=False)
    scan_in_progress = serializers.BooleanField(required=False, default=False)

    # Statistics
    total_files_monitored = serializers.IntegerField()
    changes_today = serializers.IntegerField()
    changes_this_week = serializers.IntegerField()

    # System info
    uptime = serializers.DurationField(required=False)
    memory_usage = serializers.FloatField(required=False)
    cpu_usage = serializers.FloatField(required=False)


class FIMChangesResponseSerializer(serializers.Serializer):
    """Serializer for FIM changes response"""

    class ChangeDetailSerializer(serializers.Serializer):
        hash = serializers.CharField()
        previous_hash = serializers.CharField(required=False, allow_null=True)
        size = serializers.IntegerField()
        last_modified = serializers.DateTimeField()
        detected_at = serializers.DateTimeField()
        type = serializers.CharField(source='item_type')
        change_id = serializers.UUIDField()

    added = serializers.DictField(
        child=ChangeDetailSerializer(),
        help_text="Added files with details"
    )
    modified = serializers.DictField(
        child=ChangeDetailSerializer(),
        help_text="Modified files with details"
    )
    deleted = serializers.DictField(
        child=ChangeDetailSerializer(),
        help_text="Deleted files with details"
    )
    renamed = serializers.DictField(
        child=serializers.DictField(),
        required=False,
        help_text="Renamed files mapping"
    )

    total_changes = serializers.IntegerField()
    changes_by_directory = serializers.DictField(
        child=serializers.IntegerField(),
        required=False
    )
    changes_by_hour = serializers.DictField(
        child=serializers.IntegerField(),
        required=False
    )

    # Pagination info
    page = serializers.IntegerField(required=False)
    page_size = serializers.IntegerField(required=False)
    total_pages = serializers.IntegerField(required=False)


class FIMLogsResponseSerializer(serializers.ModelSerializer):
    """Serializer for FIM logs"""

    directory_path = serializers.CharField(
        source='directory.path', 
        read_only=True,
        allow_null=True
    )
    file_path = serializers.CharField(
        source='file_metadata.item_path',
        read_only=True,
        allow_null=True
    )
    level_display = serializers.CharField(source='get_level_display', read_only=True)
    log_type_display = serializers.CharField(source='get_log_type_display', read_only=True)

    class Meta:
        model = FIMLog
        fields = [
            'id', 'log_type', 'log_type_display', 'level', 'level_display',
            'message', 'details', 'directory', 'directory_path',
            'file_metadata', 'file_path', 'timestamp', 'username', 'ip_address'
        ]
        read_only_fields = fields


class BackupRecordSerializer(serializers.ModelSerializer):
    """Serializer for BackupRecord model"""

    file_name = serializers.SerializerMethodField()
    backup_type_display = serializers.CharField(source='get_backup_type_display', read_only=True)
    size_formatted = serializers.SerializerMethodField()
    age = serializers.SerializerMethodField()

    class Meta:
        model = BackupRecord
        fields = [
            'id', 'backup_type', 'backup_type_display',
            'original_path', 'backup_path', 'file_name',
            'hash', 'size', 'size_formatted',
            'backed_up_at', 'expires_at', 'age',
            'file_metadata', 'backed_up_by',
            'is_active', 'restored', 'restore_count'
        ]
        read_only_fields = fields

    def get_file_name(self, obj):
        """Extract filename from path"""
        import os
        return os.path.basename(obj.original_path)

    def get_size_formatted(self, obj):
        """Format file size"""
        if not obj.size:
            return "0 B"

        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if obj.size < 1024.0:
                return f"{obj.size:.2f} {unit}"
            obj.size /= 1024.0
        return f"{obj.size:.2f} PB"

    def get_age(self, obj):
        """Calculate age of backup"""
        return timezone.now() - obj.backed_up_at


class ExclusionPatternSerializer(serializers.ModelSerializer):
    """Serializer for ExclusionPattern model"""

    pattern_type_display = serializers.CharField(
        source='get_pattern_type_display',
        read_only=True
    )

    directory_path = serializers.CharField(
        source='directory.path',
        read_only=True,
        allow_null=True
    )

    class Meta:
        model = ExclusionPattern
        fields = [
            'id', 'pattern', 'pattern_type', 'pattern_type_display',
            'description', 'is_global', 'directory', 'directory_path',
            'is_active', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'pattern_type_display']


class FIMConfigurationSerializer(serializers.ModelSerializer):
    """Serializer for FIMConfiguration model"""

    scan_mode_display = serializers.CharField(source='get_scan_mode_display', read_only=True)
    hash_algorithm_display = serializers.SerializerMethodField()

    class Meta:
        model = FIMConfiguration
        fields = [
            'id', 'scan_mode', 'scan_mode_display',
            'schedule_interval', 'alert_on_add', 'alert_on_modify',
            'alert_on_delete', 'hash_algorithm', 'hash_algorithm_display',
            'max_file_size', 'exclusion_patterns',
            'created_at', 'updated_at', 'created_by'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'scan_mode_display']

    def get_hash_algorithm_display(self, obj):
        """Get display name for hash algorithm"""
        algorithms = {
            'md5': 'MD5',
            'sha1': 'SHA-1',
            'sha256': 'SHA-256',
            'sha512': 'SHA-512',
        }
        return algorithms.get(obj.hash_algorithm, obj.hash_algorithm)


# ==================== Statistics Serializers ====================

class FIMStatisticsSerializer(serializers.Serializer):
    """Serializer for FIM statistics"""

    # Directory stats
    total_directories = serializers.IntegerField()
    active_directories = serializers.IntegerField()
    total_files_monitored = serializers.IntegerField()

    # Change stats
    total_changes = serializers.IntegerField()
    changes_today = serializers.IntegerField()
    changes_this_week = serializers.IntegerField()
    changes_by_type = serializers.DictField(child=serializers.IntegerField())

    # Backup stats
    total_backups = serializers.IntegerField()
    backup_size_total = serializers.IntegerField()
    successful_restores = serializers.IntegerField()

    # Performance stats
    avg_scan_time = serializers.FloatField()
    last_scan_duration = serializers.FloatField()

    # Timeline
    changes_by_day = serializers.DictField(child=serializers.IntegerField())
    changes_by_hour = serializers.DictField(child=serializers.IntegerField())

    # Top directories by changes
    top_directories = serializers.ListField(
        child=serializers.DictField(),
        required=False
    )


# ==================== Webhook/Notification Serializers ====================

class FIMAlertSerializer(serializers.Serializer):
    """Serializer for FIM alerts"""

    alert_id = serializers.UUIDField()
    alert_type = serializers.CharField()  # 'add', 'modify', 'delete', 'rename'
    severity = serializers.CharField()    # 'info', 'warning', 'critical'

    # File info
    directory = serializers.CharField()
    file_path = serializers.CharField()
    full_path = serializers.CharField()

    # Change details
    old_hash = serializers.CharField(allow_null=True)
    new_hash = serializers.CharField(allow_null=True)
    old_size = serializers.IntegerField(allow_null=True)
    new_size = serializers.IntegerField(allow_null=True)

    # Metadata
    timestamp = serializers.DateTimeField()
    detected_by = serializers.CharField()

    # Additional context
    user_info = serializers.DictField(required=False)
    process_info = serializers.DictField(required=False)
    suggestions = serializers.ListField(child=serializers.CharField(), required=False)
