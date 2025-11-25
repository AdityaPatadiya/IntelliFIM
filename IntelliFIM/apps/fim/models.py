from django.db import models

class Directory(models.Model):
    path = models.CharField(max_length=500, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'directories'
        app_label = 'fim'

    def __str__(self):
        return self.path
    

class FileMetadata(models.Model):
    STATUS_CHOICES = [
        ('current', 'Current'),
        ('added', 'Added'),
        ('modified', 'Modified'),
        ('deleted', 'Deleted'),
    ]

    ITEM_TYPE_CHOICES = [
        ('file', 'File'),
        ('folder', 'Folder'),
    ]

    directory = models.ForeignKey(Directory, on_delete=models.CASCADE, related_name='files')
    item_path = models.CharField(max_length=500)
    item_type = models.CharField(max_length=10, choices=ITEM_TYPE_CHOICES)
    hash = models.CharField(max_length=128)
    last_modified = models.DateTimeField()
    status = models.CharField(max_length=50, choices=STATUS_CHOICES)
    detected_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'file_metadata'
        app_label = 'fim'

    def __str__(self):
        return f"{self.item_path} ({self.status})"
