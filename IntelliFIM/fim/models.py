"""
Django models for File Integrity Monitoring
"""
from django.db import models
from django.core.validators import MinLengthValidator
from django.contrib.auth import get_user_model
import uuid


class Directory(models.Model):
    """Directory model for storing monitored directories"""
    id = models.AutoField(primary_key=True)
    path = models.CharField(
        max_length=500,
        unique=True,
        help_text="Full path to the directory being monitored"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True, help_text="Whether monitoring is active")
    last_scan = models.DateTimeField(null=True, blank=True, help_text="Last scan timestamp")

    # Monitoring settings
    recursive = models.BooleanField(default=True, help_text="Monitor subdirectories recursively")
    scan_interval = models.IntegerField(default=300, help_text="Scan interval in seconds")

    @property
    def file_count(self):
        """Get count of files in directory"""
        return self.files.filter(status='current').count()  # type:ignore
    
    def get_file_count_display(self):
        """Admin display method"""
        return self.file_count
    get_file_count_display.short_description = 'File Count'  # type:ignore
    
    def last_change_time(self):
        """Get timestamp of last change"""
        last_change = self.files.exclude(status='current').order_by('-detected_at').first()  # type: ignore
        return last_change.detected_at if last_change else None

    class Meta:
        db_table = 'directories'
        verbose_name = 'Directory'
        verbose_name_plural = 'Directories'
        indexes = [
            models.Index(fields=['path']),
            models.Index(fields=['is_active']),
            models.Index(fields=['created_at']),
        ]
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.path} ({'Active' if self.is_active else 'Inactive'})"

    def save(self, *args, **kwargs):
        # Ensure path is normalized
        import os
        if self.path:
            self.path = os.path.normpath(self.path)
        super().save(*args, **kwargs)


class FileMetadata(models.Model):
    """File metadata for baseline and detected changes"""

    FILE_STATUS_CHOICES = [
        ('current', 'Current - Baseline'),
        ('added', 'Added - New File'),
        ('modified', 'Modified - Changed'),
        ('deleted', 'Deleted - Removed'),
        ('renamed', 'Renamed - Moved/Renamed'),
    ]

    FILE_TYPE_CHOICES = [
        ('file', 'File'),
        ('directory', 'Directory'),
        ('symlink', 'Symbolic Link'),
        ('other', 'Other'),
    ]

    id = models.AutoField(primary_key=True)

    # ForeignKey to Directory
    directory = models.ForeignKey(
        Directory,
        on_delete=models.CASCADE,
        related_name='files',
        db_index=True,
        help_text="Directory containing this file"
    )

    # File information
    item_path = models.CharField(
        max_length=500,
        db_index=True,
        help_text="Relative path from the monitored directory"
    )
    item_type = models.CharField(
        max_length=10,
        choices=FILE_TYPE_CHOICES,
        default='file',
        help_text="Type of file system item"
    )

    # File integrity data
    hash = models.CharField(
        max_length=128,
        null=True,
        blank=True,
        validators=[MinLengthValidator(32)],
        help_text="SHA-256 hash of file content"
    )
    size = models.BigIntegerField(
        null=True,
        blank=True,
        help_text="File size in bytes"
    )

    # File metadata
    permissions = models.CharField(
        max_length=10,
        null=True,
        blank=True,
        help_text="File permissions (e.g., 'rw-r--r--')"
    )
    owner = models.CharField(
        max_length=100,
        null=True,
        blank=True,
        help_text="File owner"
    )
    group = models.CharField(
        max_length=100,
        null=True,
        blank=True,
        help_text="File group"
    )

    # Timestamps
    last_modified = models.DateTimeField(
        help_text="Last modification time from filesystem"
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="When this record was created"
    )
    detected_at = models.DateTimeField(
        auto_now_add=True,
        help_text="When this change was detected"
    )

    # Monitoring status
    status = models.CharField(
        max_length=50,
        choices=FILE_STATUS_CHOICES,
        default='current',
        db_index=True,
        help_text="Current status of the file"
    )

    # Change tracking
    previous_hash = models.CharField(
        max_length=128,
        null=True,
        blank=True,
        help_text="Previous hash before modification"
    )
    change_id = models.UUIDField(
        default=uuid.uuid4,
        editable=False,
        unique=True,
        help_text="Unique identifier for this change event"
    )

    # Audit fields
    reported = models.BooleanField(
        default=False,
        help_text="Whether this change has been reported"
    )
    restored = models.BooleanField(
        default=False,
        help_text="Whether this file has been restored from backup"
    )

    class Meta:
        db_table = 'file_metadata'
        verbose_name = 'File Metadata'
        verbose_name_plural = 'File Metadata'
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['detected_at']),
            models.Index(fields=['directory', 'item_path']),
            models.Index(fields=['directory', 'status']),
        ]
        ordering = ['-detected_at']
        unique_together = [['directory', 'item_path', 'status']]

    def __str__(self):
        return f"{self.item_path} - {self.get_status_display()} ({self.directory.path})"

    @property
    def full_path(self):
        """Get the full absolute path of the file"""
        import os
        return os.path.join(self.directory.path, self.item_path)


class FIMConfiguration(models.Model):
    """Configuration for FIM monitoring"""

    SCAN_MODE_CHOICES = [
        ('realtime', 'Real-time Monitoring'),
        ('scheduled', 'Scheduled Scans'),
        ('hybrid', 'Hybrid (Real-time + Scheduled)'),
    ]

    id = models.AutoField(primary_key=True)

    # Core settings
    scan_mode = models.CharField(
        max_length=20,
        choices=SCAN_MODE_CHOICES,
        default='realtime',
        help_text="Monitoring mode"
    )

    # Schedule settings (if scheduled or hybrid)
    schedule_interval = models.IntegerField(
        default=300,
        help_text="Scan interval in seconds for scheduled mode"
    )

    # Alert settings
    alert_on_add = models.BooleanField(default=True)
    alert_on_modify = models.BooleanField(default=True)
    alert_on_delete = models.BooleanField(default=True)

    # Hash algorithm
    hash_algorithm = models.CharField(
        max_length=20,
        default='sha256',
        choices=[
            ('md5', 'MD5'),
            ('sha1', 'SHA-1'),
            ('sha256', 'SHA-256'),
            ('sha512', 'SHA-512'),
        ]
    )

    # Performance settings
    max_file_size = models.BigIntegerField(
        default=104857600,  # 100MB
        help_text="Maximum file size to hash (in bytes)"
    )

    # Exclusion patterns
    exclusion_patterns = models.TextField(
        blank=True,
        help_text="Comma-separated list of exclusion patterns"
    )

    User = get_user_model()

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        User,  # Assuming you have a User model
        on_delete=models.SET_NULL,
        null=True,
        related_name='fim_configs'
    )

    class Meta:
        db_table = 'fim_configurations'
        verbose_name = 'FIM Configuration'
        verbose_name_plural = 'FIM Configurations'

    def __str__(self):
        return f"FIM Config ({self.get_scan_mode_display()})"


class FIMLog(models.Model):
    """Log entries for FIM operations"""

    LOG_LEVEL_CHOICES = [
        ('info', 'Info'),
        ('warning', 'Warning'),
        ('error', 'Error'),
        ('critical', 'Critical'),
    ]

    LOG_TYPE_CHOICES = [
        ('scan', 'Scan'),
        ('change', 'Change Detection'),
        ('alert', 'Alert'),
        ('system', 'System'),
        ('backup', 'Backup'),
        ('restore', 'Restore'),
    ]

    id = models.AutoField(primary_key=True)
    log_type = models.CharField(max_length=20, choices=LOG_TYPE_CHOICES)
    level = models.CharField(max_length=20, choices=LOG_LEVEL_CHOICES)
    message = models.TextField()
    details = models.JSONField(null=True, blank=True)

    # Foreign keys
    directory = models.ForeignKey(
        Directory,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='logs'
    )
    file_metadata = models.ForeignKey(
        FileMetadata,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='logs'
    )

    # Timestamps
    timestamp = models.DateTimeField(auto_now_add=True)

    # User info
    username = models.CharField(max_length=150, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        db_table = 'fim_logs'
        verbose_name = 'FIM Log'
        verbose_name_plural = 'FIM Logs'
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['log_type', 'level']),
            models.Index(fields=['directory', 'timestamp']),
        ]
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.timestamp} [{self.level}] {self.log_type}: {self.message[:100]}"


class BackupRecord(models.Model):
    """Records of file backups"""
    
    BACKUP_TYPE_CHOICES = [
        ('automatic', 'Automatic'),
        ('manual', 'Manual'),
        ('restore', 'Restore Point'),
    ]

    id = models.AutoField(primary_key=True)
    backup_type = models.CharField(max_length=20, choices=BACKUP_TYPE_CHOICES)
    
    # File information
    original_path = models.CharField(max_length=500)
    backup_path = models.CharField(max_length=500)

    # File metadata
    hash = models.CharField(max_length=128)
    size = models.BigIntegerField()

    # Foreign keys
    file_metadata = models.ForeignKey(
        FileMetadata,
        on_delete=models.CASCADE,
        related_name='backups'
    )

    # Timestamps
    backed_up_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    # User info
    backed_up_by = models.CharField(max_length=150)

    # Status
    is_active = models.BooleanField(default=True)
    restored = models.BooleanField(default=False)
    restore_count = models.IntegerField(default=0)

    class Meta:
        db_table = 'backup_records'
        verbose_name = 'Backup Record'
        verbose_name_plural = 'Backup Records'
        indexes = [
            models.Index(fields=['backed_up_at']),
            models.Index(fields=['original_path']),
            models.Index(fields=['file_metadata']),
        ]
        ordering = ['-backed_up_at']
    
    def __str__(self):
        return f"Backup of {self.original_path} ({self.backup_type})"


class ExclusionPattern(models.Model):
    """Patterns to exclude from monitoring"""

    PATTERN_TYPE_CHOICES = [
        ('glob', 'Glob Pattern'),
        ('regex', 'Regular Expression'),
        ('extension', 'File Extension'),
        ('path', 'Path Contains'),
    ]

    id = models.AutoField(primary_key=True)

    # Pattern info
    pattern = models.CharField(max_length=500)
    pattern_type = models.CharField(max_length=20, choices=PATTERN_TYPE_CHOICES)
    description = models.TextField(blank=True)

    # Scope
    is_global = models.BooleanField(
        default=False,
        help_text="Apply to all directories"
    )

    # Foreign keys
    directory = models.ForeignKey(
        Directory,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='exclusions'
    )

    # Active/inactive
    is_active = models.BooleanField(default=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'exclusion_patterns'
        verbose_name = 'Exclusion Pattern'
        verbose_name_plural = 'Exclusion Patterns'
        indexes = [
            models.Index(fields=['is_global']),
            models.Index(fields=['is_active']),
            models.Index(fields=['directory', 'is_active']),
        ]
        ordering = ['-created_at']

    def __str__(self):
        scope = "Global" if self.is_global else f"Dir: {self.directory.path}"
        return f"{scope} - {self.pattern} ({self.get_pattern_type_display()})"
