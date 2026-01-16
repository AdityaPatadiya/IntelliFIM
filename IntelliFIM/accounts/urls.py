from django.urls import path
from .views import (
    RegisterView,
    LoginView,
    CurrentUserView,
    UserListView,
    UserCreateView,
    UserDetailView,
    ToggleAdminStatusView,
)
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('me/', CurrentUserView.as_view(), name='current_user'),
    path('users/', UserListView.as_view(), name='user_list'),
    path('users/create/', UserCreateView.as_view(), name='user_create'),
    path('users/<int:id>/', UserDetailView.as_view(), name='user_detail'),
    path('users/<int:user_id>/admin/', ToggleAdminStatusView.as_view(), name='toggle_admin'),
]
