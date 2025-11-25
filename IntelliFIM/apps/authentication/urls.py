from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('me/', views.get_me, name='get_me'),
    path('users/', views.get_all_users, name='get_all_users'),
    path('users/create/', views.create_user, name='create_user'),
    path('users/<int:user_id>/', views.update_user, name='update_user'),
    path('users/<int:user_id>/delete/', views.delete_user, name='delete_user'),
    path('users/<int:user_id>/admin/', views.toggle_admin_status, name='toggle_admin_status'),
]
