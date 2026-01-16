from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'directories', views.DirectoryViewSet, basename='directory')
router.register(r'files', views.FileMetadataViewSet, basename='filemetadata')

urlpatterns = [
    path('', include(router.urls)),
    
    # FIM Operations with Celery
    path('start/', views.FIMStartView.as_view(), name='fim-start'),
    path('stop/', views.FIMStopView.as_view(), name='fim-stop'),
    path('scan/', views.FIMScanView.as_view(), name='fim-scan'),
    path('restore/', views.FIMRestoreView.as_view(), name='fim-restore'),
    path('reset-baseline/', views.FIMResetBaselineView.as_view(), name='fim-reset-baseline'),
    path('export/', views.FIMExportView.as_view(), name='fim-export'),
    
    # Status and data endpoints
    path('status/', views.FIMStatusView.as_view(), name='fim-status'),
    path('changes/', views.FIMChangesView.as_view(), name='fim-changes'),
    path('logs/', views.FIMLogsView.as_view(), name='fim-logs'),
    path('baseline/', views.FIMGetBaselineView.as_view(), name='fim-baseline'),
    path('statistics/', views.FIMStatisticsView.as_view(), name='fim-statistics'),
    path('api/fim/stream/', views.FIMStreamView.as_view()),

    # Task management
    path('tasks/<str:task_id>/', views.TaskStatusView.as_view(), name='task-status'),
    
    # Add path (also available via POST to /directories/)
    path('add-path/', views.FIMAddPathView.as_view(), name='fim-add-path'),
]
