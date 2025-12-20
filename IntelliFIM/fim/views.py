from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework.viewsets import ModelViewSet
from django.shortcuts import get_object_or_404
from django.db import transaction
from django.utils import timezone
from django.core.cache import cache
from celery.result import AsyncResult
from datetime import timedelta
import os
import json
from pathlib import Path

from .models import Directory, FileMetadata, FIMLog, BackupRecord
from .serializers import (
    FIMStartRequestSerializer, FIMStopRequestSerializer,
    FIMAddPathRequestSerializer, FIMRestoreRequestSerializer,
    FIMStatusResponseSerializer, FIMChangesResponseSerializer,
    FIMLogsResponseSerializer, DirectorySerializer,
    FileMetadataSerializer, FIMStatisticsSerializer,
    FIMResetBaselineRequestSerializer, FIMScanRequestSerializer
)
from .tasks import (
    start_fim_monitoring_task,
    stop_fim_monitoring_task,
    reset_baseline_task,
    export_fim_report,
    calculate_baseline_for_directory,
)

try:
    from .core.FIM import MonitorChanges
    fim_monitor = MonitorChanges()
except ImportError:
    # Fallback if the module isn't available yet
    class MockMonitorChanges:
        def __init__(self):
            self.current_directories = []
            self.observer = None
    
    fim_monitor = MockMonitorChanges()


class IsAdminUser(permissions.BasePermission):
    """Custom permission to only allow admin users"""
    
    def has_permission(self, request, view):
        return request.user and (request.user.is_staff or request.user.is_superuser)


class TaskStatusView(APIView):
    """Get status of a Celery task"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, task_id):
        try:
            result = AsyncResult(task_id)
            
            # Check cache for additional info
            cache_key = f"task_{task_id}"
            cached_info = cache.get(cache_key, {})
            
            response_data = {
                'task_id': task_id,
                'status': result.status,
                'date_done': result.date_done.isoformat() if result.date_done else None,
                'result': result.result if result.ready() else None,
                'cached_info': cached_info
            }
            
            return Response(response_data)
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class FIMAddPathView(APIView):
    """Add directory to monitor"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def post(self, request):
        serializer = FIMAddPathRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            directory_path = serializer.validated_data['directory']
            
            # Check if directory exists
            if not os.path.exists(directory_path):
                return Response(
                    {"detail": f"Directory does not exist: {directory_path}"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Check if already monitored
            if Directory.objects.filter(path=directory_path).exists():
                return Response(
                    {"detail": "Directory is already being monitored"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Create directory record
            directory = Directory.objects.create(
                path=directory_path,
                recursive=serializer.validated_data.get('recursive', True),
                scan_interval=serializer.validated_data.get('scan_interval', 300),
                is_active=True
            )
            
            # Update in-memory directories if monitoring is active
            if hasattr(fim_monitor, 'current_directories'):
                if directory_path not in fim_monitor.current_directories:
                    fim_monitor.current_directories.append(directory_path)
            
            return Response({
                "message": "Directory added to monitoring",
                "directory": directory_path,
                "id": directory.id,
                "total_monitored": Directory.objects.filter(is_active=True).count()
            })
            
        except Exception as e:
            return Response(
                {"detail": f"Failed to add directory: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class FIMStartView(APIView):
    """Start FIM monitoring for directories using Celery"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def post(self, request):
        serializer = FIMStartRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Start Celery task
            task = start_fim_monitoring_task.delay(
                user_id=request.user.id,
                username=request.user.username,
                directories=serializer.validated_data['directories'],
                excluded_files=serializer.validated_data.get('excluded_files', []),
                recursive=serializer.validated_data.get('recursive', True),
                scan_interval=serializer.validated_data.get('scan_interval', 300)
            )
            
            return Response({
                "message": "FIM monitoring task submitted",
                "task_id": task.id,
                "status_endpoint": f"/api/fim/tasks/{task.id}/",
                "directories": serializer.validated_data['directories']
            })
            
        except Exception as e:
            return Response(
                {"detail": f"Failed to start monitoring task: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class FIMStopView(APIView):
    """Stop FIM monitoring using Celery"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def post(self, request):
        serializer = FIMStopRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            task = stop_fim_monitoring_task.delay(
                username=request.user.username,
                directories=serializer.validated_data['directories'],
                remove_from_db=serializer.validated_data.get('remove_from_db', False)
            )
            
            return Response({
                "message": "FIM stop task submitted",
                "task_id": task.id,
                "status_endpoint": f"/api/fim/tasks/{task.id}/"
            })
            
        except Exception as e:
            return Response(
                {"detail": f"Failed to stop monitoring: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class FIMScanView(APIView):
    """Perform manual scan using Celery"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def post(self, request):
        serializer = FIMScanRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            task = perform_manual_scan.delay(
                username=request.user.username,
                directories=serializer.validated_data.get('directories', []),
                deep_scan=serializer.validated_data.get('deep_scan', False)
            )
            
            return Response({
                "message": "Manual scan task submitted",
                "task_id": task.id,
                "status_endpoint": f"/api/fim/tasks/{task.id}/"
            })
            
        except Exception as e:
            return Response(
                {"detail": f"Failed to start scan: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class FIMRestoreView(APIView):
    """Restore files using Celery"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def post(self, request):
        serializer = FIMRestoreRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            task = restore_file_task.delay(
                username=request.user.username,
                path_to_restore=serializer.validated_data['path_to_restore'],
                backup_id=serializer.validated_data.get('backup_id'),
                restore_location=serializer.validated_data.get('restore_location'),
                overwrite=serializer.validated_data.get('overwrite', True)
            )
            
            return Response({
                "message": "Restore task submitted",
                "task_id": task.id,
                "status_endpoint": f"/api/fim/tasks/{task.id}/"
            })
            
        except Exception as e:
            return Response(
                {"detail": f"Failed to start restore: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class FIMResetBaselineView(APIView):
    """Reset baseline using Celery"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def post(self, request):
        serializer = FIMResetBaselineRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            task = reset_baseline_task.delay(
                username=request.user.username,
                directories=serializer.validated_data['directories']
            )
            
            return Response({
                "message": "Baseline reset task submitted",
                "task_id": task.id,
                "status_endpoint": f"/api/fim/tasks/{task.id}/"
            })
            
        except Exception as e:
            return Response(
                {"detail": f"Failed to reset baseline: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class FIMExportView(APIView):
    """Export FIM reports using Celery"""
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        start_date = request.data.get('start_date')
        end_date = request.data.get('end_date')
        report_type = request.data.get('report_type', 'changes')
        
        if not start_date or not end_date:
            return Response(
                {"detail": "start_date and end_date are required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            task = export_fim_report.delay(start_date, end_date, report_type)
            
            return Response({
                "message": "Report generation task submitted",
                "task_id": task.id,
                "status_endpoint": f"/api/fim/tasks/{task.id}/"
            })
            
        except Exception as e:
            return Response(
                {"detail": f"Failed to generate report: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class FIMStatusView(APIView):
    """Get FIM monitoring status"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        try:
            # Get monitoring status from your existing MonitorChanges instance
            is_monitoring = (
                hasattr(fim_monitor, 'observer') and
                fim_monitor.observer is not None and
                fim_monitor.observer.is_alive()
            )
            
            # Get all directories from database
            all_directories = list(Directory.objects.values_list('path', flat=True))
            
            # Get active directories
            active_directories = []
            if hasattr(fim_monitor, "current_directories"):
                active_directories = fim_monitor.current_directories
            
            # Statistics
            total_files = FileMetadata.objects.filter(status='current').count()
            today = timezone.now().date()
            week_ago = today - timedelta(days=7)
            
            changes_today = FileMetadata.objects.filter(
                detected_at__date=today
            ).exclude(status='current').count()
            
            changes_this_week = FileMetadata.objects.filter(
                detected_at__date__gte=week_ago
            ).exclude(status='current').count()
            
            response_data = {
                "is_monitoring": is_monitoring,
                "watched_directories": all_directories,
                "active_directories": active_directories,
                "total_configured": len(all_directories),
                "total_active": len(active_directories),
                "total_files_monitored": total_files,
                "changes_today": changes_today,
                "changes_this_week": changes_this_week,
            }
            
            serializer = FIMStatusResponseSerializer(response_data)
            return Response(serializer.data)
            
        except Exception as e:
            return Response(
                {"detail": f"Failed to get status: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class FIMChangesView(APIView):
    """Get detected changes"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        directory = request.GET.get('directory', None)
        
        try:
            # Build query
            changes_qs = FileMetadata.objects.select_related('directory').exclude(status='current')
            
            if directory:
                changes_qs = changes_qs.filter(directory__path=directory)
            
            changes = changes_qs.order_by('-detected_at')
            
            # Organize changes by type
            changes_dict = {"added": {}, "modified": {}, "deleted": {}, "renamed": {}}
            
            for change in changes:
                change_info = {
                    "hash": change.hash,
                    "previous_hash": change.previous_hash,
                    "size": change.size,
                    "last_modified": change.last_modified,
                    "detected_at": change.detected_at,
                    "type": change.item_type,
                    "change_id": str(change.change_id)
                }
                
                if change.status in changes_dict:
                    changes_dict[change.status][change.item_path] = change_info
                else:
                    changes_dict["modified"][change.item_path] = change_info
            
            total_changes = sum(len(changes_dict[status]) for status in changes_dict)
            
            response_data = {
                "added": changes_dict["added"],
                "modified": changes_dict["modified"],
                "deleted": changes_dict["deleted"],
                "renamed": changes_dict["renamed"],
                "total_changes": total_changes
            }
            
            serializer = FIMChangesResponseSerializer(response_data)
            return Response(serializer.data)
            
        except Exception as e:
            return Response(
                {"detail": f"Failed to get changes: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class FIMLogsView(APIView):
    """Retrieve FIM logs"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        directory = request.GET.get('directory', None)
        
        try:
            logs_dir = Path(__file__).resolve().parent.parent.parent / "logs"
            logs_data = []
            
            if directory:
                # Get specific directory logs
                norm_dir = Path(directory).resolve().name
                log_file = logs_dir / f"FIM_{norm_dir}.log"
                
                if log_file.exists():
                    with open(log_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                        logs_data.append({
                            "directory": directory,
                            "log_file": str(log_file),
                            "content": content
                        })
                else:
                    return Response(
                        {"detail": f"No logs found for directory: {directory}"},
                        status=status.HTTP_404_NOT_FOUND
                    )
            else:
                # Get all logs
                for log_path in logs_dir.glob("FIM_*.log"):
                    directory_name = log_path.stem.replace("FIM_", "")
                    
                    with open(log_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        logs_data.append({
                            "directory": directory_name,
                            "log_file": str(log_path),
                            "content": content
                        })
            
            if not logs_data:
                return Response(
                    {"detail": "No FIM logs found"},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            serializer = FIMLogsResponseSerializer(logs_data, many=True)
            return Response(serializer.data)
            
        except Exception as e:
            return Response(
                {"detail": f"Failed to retrieve logs: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class DirectoryViewSet(ModelViewSet):
    """API endpoint for managing directories"""
    queryset = Directory.objects.all()
    serializer_class = DirectorySerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def create(self, request, *args, **kwargs):
        serializer = FIMAddPathRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            directory_path = serializer.validated_data['directory']
            
            # Check if directory exists
            if not os.path.exists(directory_path):
                return Response(
                    {"detail": f"Directory does not exist: {directory_path}"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Check if already monitored
            if Directory.objects.filter(path=directory_path).exists():
                return Response(
                    {"detail": "Directory is already being monitored"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Create directory record
            directory = Directory.objects.create(
                path=directory_path,
                recursive=serializer.validated_data.get('recursive', True),
                scan_interval=serializer.validated_data.get('scan_interval', 300),
                is_active=True
            )
            
            # Update in-memory directories if monitoring is active
            if hasattr(fim_monitor, 'current_directories'):
                if directory_path not in fim_monitor.current_directories:
                    fim_monitor.current_directories.append(directory_path)
            
            return Response({
                "message": "Directory added to monitoring",
                "directory": directory_path,
                "id": directory.id,
                "total_monitored": Directory.objects.filter(is_active=True).count()
            })
            
        except Exception as e:
            return Response(
                {"detail": f"Failed to add directory: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class FileMetadataViewSet(ModelViewSet):
    """API endpoint for file metadata"""
    queryset = FileMetadata.objects.all()
    serializer_class = FileMetadataSerializer
    permission_classes = [permissions.IsAuthenticated]
    filterset_fields = ['status', 'item_type', 'directory']
    search_fields = ['item_path', 'hash']
    ordering_fields = ['detected_at', 'last_modified', 'size']
    ordering = ['-detected_at']


class FIMStatisticsView(APIView):
    """Get FIM statistics"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        try:
            # Calculate statistics
            total_directories = Directory.objects.count()
            active_directories = Directory.objects.filter(is_active=True).count()
            total_files = FileMetadata.objects.filter(status='current').count()
            
            # Change statistics
            total_changes = FileMetadata.objects.exclude(status='current').count()
            
            today = timezone.now().date()
            week_ago = today - timedelta(days=7)
            
            changes_today = FileMetadata.objects.filter(
                detected_at__date=today
            ).exclude(status='current').count()
            
            changes_this_week = FileMetadata.objects.filter(
                detected_at__date__gte=week_ago
            ).exclude(status='current').count()
            
            # Changes by type
            changes_by_type = FileMetadata.objects.exclude(
                status='current'
            ).values('status').annotate(count=Count('id')).order_by('-count')
            
            changes_type_dict = {item['status']: item['count'] for item in changes_by_type}
            
            # Changes by day (last 30 days)
            thirty_days_ago = today - timedelta(days=30)
            changes_by_day = FileMetadata.objects.filter(
                detected_at__date__gte=thirty_days_ago
            ).exclude(status='current').extra(
                {'date': "date(detected_at)"}
            ).values('date').annotate(count=Count('id')).order_by('date')
            
            changes_day_dict = {str(item['date']): item['count'] for item in changes_by_day}
            
            # Changes by hour
            changes_by_hour = FileMetadata.objects.exclude(status='current').extra(
                {'hour': "strftime('%H', detected_at)"}
            ).values('hour').annotate(count=Count('id')).order_by('hour')
            
            changes_hour_dict = {item['hour']: item['count'] for item in changes_by_hour}
            
            # Top directories by changes
            top_directories = Directory.objects.annotate(
                change_count=Count('files', filter=~Q(files__status='current'))
            ).filter(change_count__gt=0).order_by('-change_count')[:10]
            
            top_dirs_list = [
                {
                    'path': dir.path,
                    'change_count': dir.change_count,
                    'file_count': dir.files.filter(status='current').count()
                }
                for dir in top_directories
            ]
            
            # Backup statistics
            total_backups = BackupRecord.objects.count()
            successful_restores = BackupRecord.objects.filter(restored=True).count()
            
            response_data = {
                "total_directories": total_directories,
                "active_directories": active_directories,
                "total_files_monitored": total_files,
                "total_changes": total_changes,
                "changes_today": changes_today,
                "changes_this_week": changes_this_week,
                "changes_by_type": changes_type_dict,
                "total_backups": total_backups,
                "successful_restores": successful_restores,
                "changes_by_day": changes_day_dict,
                "changes_by_hour": changes_hour_dict,
                "top_directories": top_dirs_list,
            }
            
            serializer = FIMStatisticsSerializer(response_data)
            return Response(serializer.data)
            
        except Exception as e:
            return Response(
                {"detail": f"Failed to get statistics: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class FIMGetBaselineView(APIView):
    """Get current baseline data"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        directory = request.GET.get('directory', None)
        
        try:
            # Query for baseline (current) files
            baseline_qs = FileMetadata.objects.select_related('directory').filter(status='current')
            
            if directory:
                baseline_qs = baseline_qs.filter(directory__path=directory)
                if not baseline_qs.exists():
                    return Response(
                        {"detail": f"Directory not found: {directory}"},
                        status=status.HTTP_404_NOT_FOUND
                    )
            
            baseline_data = baseline_qs
            
            # Organize by directory
            baseline_dict = {}
            for item in baseline_data:
                dir_path = item.directory.path
                if dir_path not in baseline_dict:
                    baseline_dict[dir_path] = {}
                
                baseline_dict[dir_path][item.item_path] = {
                    "type": item.item_type,
                    "hash": item.hash,
                    "size": item.size,
                    "last_modified": item.last_modified,
                    "detected_at": item.detected_at
                }
            
            return Response({
                "baseline": baseline_dict,
                "total_items": baseline_data.count()
            })
            
        except Exception as e:
            return Response(
                {"detail": f"Failed to get baseline: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class FIMStreamDebugView(APIView):
    """Debug endpoint for SSE stream (placeholder for real-time events)"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        return Response({
            "message": "SSE streaming not implemented in Django. Use polling or WebSocket.",
            "suggestions": [
                "Use Django Channels for real-time updates",
                "Implement WebSocket endpoint",
                "Use polling with /api/fim/changes/ endpoint"
            ]
        })
