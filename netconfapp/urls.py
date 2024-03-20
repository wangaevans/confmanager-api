from django.urls import path
from . import views

urlpatterns = [
    path('configuration/logs/', views.show_configuration_logs, name='show-configuration-logs'),
    path('device/<uuid:pk>/delete/', views.delete_item, name='delete-device'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('device/<uuid:device_pk>/rollback/', views.rollback_configuration, name='rollback-configuration'),
    path('device/<uuid:pk>/configurations/', views.view_configurations, name='view-configurations'),
    path('devices/by_os/', views.view_devices_by_os, name='view-devices-by-os'),
    path('device/<uuid:device_pk>/configuration/<uuid:config_pk>/', views.view_single_configuration, name='view-single-configuration'),
    path('device/<uuid:pk>/modify-connection/', views.modify_device_connection, name='modify-device-connection'),
    path('device/<uuid:pk>/configure/', views.configure_device, name='configure-device'),
    path('configure-multiple-devices/', views.configure_multiple_devices, name='configure-multiple-devices'),
    path('connect-to-device/', views.connect_to_device, name='connect-to-device'),
]
