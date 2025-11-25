from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.db import transaction
import os
from pathlib import Path
from .models import Directory, FileMetadata
from .serializers import (FIMStartRequestSerializer, FIMStatusResponseSerializer,
                         FIMChangesResponseSerializer)
from src.FIM.FIM import MonitorChanges
from src.utils.backup import Backup

fim_monitor = MonitorChanges()

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def start_fim_monitoring(request):
    if not request.user.is_admin:
        return Response({'detail': 'Admin access required'}, status=status.HTTP_403_FORBIDDEN)
    
    serializer = FIMStartRequestSerializer(data=request.data)
    if serializer.is_valid():
        directories = serializer.validated_data['directories']
        excluded_files = serializer.validated_data.get('excluded_files', [])
        
        # Verify directories exist
        for directory in directories:
            if not os.path.exists(directory):
                return Response(
                    {'detail': f'Directory does not exist: {directory}'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        # Create directory records
        with transaction.atomic(using='fim_db'):
            for directory in directories:
                Directory.objects.using('fim_db').get_or_create(path=directory)
        
        # Start monitoring (you might want to use Celery for background tasks)
        fim_monitor.monitor_changes(
            request.user.username,
            directories,
            excluded_files,
            None  # DB session - will need to adapt for Django ORM
        )
        
        return Response({
            'message': 'FIM monitoring started successfully',
            'directories': directories,
            'excluded_files': excluded_files
        })
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_fim_status(request):
    is_monitoring = (
        hasattr(fim_monitor, 'observer') and 
        fim_monitor.observer.is_alive()
    )
    
    dir_records = Directory.objects.using('fim_db').all()
    watched_directories = [str(d.path) for d in dir_records]
    
    response_data = {
        'is_monitoring': is_monitoring,
        'watched_directories': watched_directories,
        'total_watched': len(watched_directories)
    }
    
    serializer = FIMStatusResponseSerializer(response_data)
    return Response(serializer.data)
