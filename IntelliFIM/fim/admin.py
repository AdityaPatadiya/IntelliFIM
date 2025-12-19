# fim/admin.py
from django.contrib import admin
from .models import Directory, FileMetadata, FIMConfiguration, FIMLog, BackupRecord, ExclusionPattern


@admin.register(Directory)
class DirectoryAdmin(admin.ModelAdmin):
    list_display = ['path', 'is_active', 'get_file_count', 'last_scan']
    list_filter = ['is_active', 'created_at']
    search_fields = ['path']
    readonly_fields = ['created_at', 'last_scan', 'get_file_count']
    
    def get_file_count(self, obj):
        return obj.files.filter(status='current').count()
    get_file_count.short_description = 'File Count'


@admin.register(FileMetadata)
class FileMetadataAdmin(admin.ModelAdmin):
    list_display = ['item_path', 'directory', 'status', 'detected_at']
    list_filter = ['status', 'item_type', 'detected_at']
    search_fields = ['item_path', 'hash']
    readonly_fields = ['detected_at', 'created_at', 'change_id']
    date_hierarchy = 'detected_at'


@admin.register(FIMConfiguration)
class FIMConfigurationAdmin(admin.ModelAdmin):
    list_display = ['scan_mode', 'hash_algorithm', 'created_at']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(FIMLog)
class FIMLogAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'log_type', 'level', 'message_short', 'username']
    list_filter = ['log_type', 'level', 'timestamp']
    search_fields = ['message', 'username']
    readonly_fields = ['timestamp']
    
    def message_short(self, obj):
        return obj.message[:100] + '...' if len(obj.message) > 100 else obj.message
    message_short.short_description = 'Message'


@admin.register(BackupRecord)
class BackupRecordAdmin(admin.ModelAdmin):
    list_display = ['original_path', 'backup_type', 'backed_up_at', 'backed_up_by']
    list_filter = ['backup_type', 'backed_up_at']
    search_fields = ['original_path', 'backup_path']


@admin.register(ExclusionPattern)
class ExclusionPatternAdmin(admin.ModelAdmin):
    list_display = ['pattern', 'pattern_type', 'is_global', 'is_active']
    list_filter = ['is_global', 'is_active', 'pattern_type']
