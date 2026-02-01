from django.urls import path
from . import views

urlpatterns = [
    path('start/', views.StartMonitoringView.as_view(), name='network-start'),
    path('stop/', views.StopMonitoringView.as_view(), name='network-stop'),
    path('status/', views.MonitorStatusView.as_view(), name='network-status'),
    path('packets/', views.RecentPacketsView.as_view(), name='network-packets'),
    path('alerts/', views.NetworkAlertsView.as_view(), name='network-alerts'),
    path('statistics/', views.DetailedStatisticsView.as_view(), name='network-statistics'),
    path('interfaces/', views.NetworkInterfacesView.as_view(), name='network-interfaces'),
    path('privileges/', views.PrivilegesView.as_view(), name='network-privileges'),
    path('elevation-methods/', views.ElevationMethodsView.as_view(), name='network-elevation-methods'),
    path('health/', views.HealthCheckView.as_view(), name='network-health'),
    path('test-socket/', views.test_raw_socket, name='test-raw-socket'),
]
