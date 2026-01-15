from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
import logging
from .models import User
from .serializers import UserCreateSerializer, UserLoginSerializer, UserResponseSerializer
from .permissions import IsAdminUser

logger = logging.getLogger(__name__)


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class RegisterView(generics.CreateAPIView):
    serializer_class = UserCreateSerializer
    permission_classes = [permissions.AllowAny]
    
    def create(self, request, *args, **kwargs):
        logger.info(f"🔍 Register attempt - Email: {request.data.get('email')}")
        
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Check if user is the first user (make them admin)
        is_first_user = User.objects.count() == 0
        if is_first_user:
            serializer.validated_data['is_admin'] = True
            serializer.validated_data['is_staff'] = True
            serializer.validated_data['is_superuser'] = True
        
        user = serializer.save()
        
        # Generate tokens
        tokens = get_tokens_for_user(user)
        
        logger.info(f"User registered - ID: {user.id}, Admin: {user.is_admin}")
        
        return Response({
            'access_token': tokens['access'],
            'refresh_token': tokens['refresh'],
            'token_type': 'bearer',
            'user': UserResponseSerializer(user).data,
            'message': f"User {user.username} registered successfully!" + 
                      (" You are the administrator." if user.is_admin else "")
        }, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = serializer.validated_data['user']
        
        # Generate tokens
        tokens = get_tokens_for_user(user)
        
        return Response({
            'access_token': tokens['access'],
            'refresh_token': tokens['refresh'],
            'token_type': 'bearer',
            'user': UserResponseSerializer(user).data,
            'message': f"Welcome back, {user.username}!" + 
                      (" (Administrator)" if user.is_admin else "")
        })


class CurrentUserView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        serializer = UserResponseSerializer(request.user)
        return Response(serializer.data)


class UserListView(generics.ListAPIView):
    serializer_class = UserResponseSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def get_queryset(self):
        return User.objects.all()


class UserCreateView(generics.CreateAPIView):
    serializer_class = UserCreateSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Remove is_admin from data for regular user creation
        if 'is_admin' in serializer.validated_data:
            serializer.validated_data.pop('is_admin')
        
        user = serializer.save()
        
        return Response({
            'user': UserResponseSerializer(user).data,
            'message': f"User {user.username} created successfully!"
        }, status=status.HTTP_201_CREATED)


class UserDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = UserResponseSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    queryset = User.objects.all()
    lookup_field = 'id'
    
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        
        if instance == request.user:
            return Response(
                {"detail": "Cannot modify your own account via this endpoint."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        
        # Handle password update
        if 'password' in request.data:
            instance.set_password(request.data['password'])
        
        self.perform_update(serializer)
        
        if getattr(instance, '_prefetched_objects_cache', None):
            instance._prefetched_objects_cache = {}
        
        return Response(serializer.data)
    
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        
        if instance == request.user:
            return Response(
                {"detail": "Cannot delete your own account."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        self.perform_destroy(instance)
        return Response({"message": "User deleted successfully"})


class ToggleAdminStatusView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def put(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {"detail": "User not found"},
                status=status.HTTP_404_NOT_FOUND
            )

        if user == request.user:
            return Response(
                {"detail": "Cannot modify your own admin status"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user.is_admin = not user.is_admin
        user.is_staff = user.is_admin  # Keep is_staff in sync with is_admin
        user.save()
        
        return Response({
            'user': UserResponseSerializer(user).data,
            'message': f"User {'promoted to' if user.is_admin else 'demoted from'} admin"
        })
