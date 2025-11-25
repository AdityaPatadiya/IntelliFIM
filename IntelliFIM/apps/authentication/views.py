from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.shortcuts import get_object_or_404
from typing import cast
from .models import User
from .serializers import (UserSerializer, UserCreateSerializer, 
                         UserLoginSerializer, UserUpdateSerializer)
@api_view(['POST'])
@permission_classes([AllowAny])
def register(request):
    serializer = UserCreateSerializer(data=request.data)
    if serializer.is_valid():
        user = cast(User, serializer.save())
        refresh = RefreshToken.for_user(user)
        return Response({
            'access_token': str(refresh.access_token),
            'token_type': 'bearer',
            'user': UserSerializer(user).data,
            'message': f"User {user.username} registered successfully!" + 
                      (" You are the administrator." if user.is_admin else "")
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
@api_view(['POST'])
@permission_classes([AllowAny])
def login(request):
    serializer = UserLoginSerializer(data=request.data)
    if serializer.is_valid():
        validated = cast(dict, serializer.validated_data)
        user_obj = validated.get('user')
        if user_obj is None:
            return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        user = cast(User, user_obj)
        refresh = RefreshToken.for_user(user)
        return Response({
            'access_token': str(refresh.access_token),
            'token_type': 'bearer',
            'user': UserSerializer(user).data,
            'message': f"Welcome back, {user.username}!" + 
                      (" (Administrator)" if user.is_admin else "")
        })
    return Response(serializer.errors, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_me(request):
    return Response(UserSerializer(request.user).data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_all_users(request):
    if not request.user.is_admin:
        return Response({'detail': 'Admin access required'}, status=status.HTTP_403_FORBIDDEN)
    
    users = User.objects.all()
    serializer = UserSerializer(users, many=True)
    return Response(serializer.data)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_user(request):
    if not request.user.is_admin:
        return Response({'detail': 'Admin access required'}, status=status.HTTP_403_FORBIDDEN)
    
    serializer = UserCreateSerializer(data=request.data)
    if serializer.is_valid():
        user = cast(User, serializer.save())
        return Response({
            'message': 'User created successfully',
            'user': UserSerializer(user).data
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_user(request, user_id):
    if not request.user.is_admin:
        return Response({'detail': 'Admin access required'}, status=status.HTTP_403_FORBIDDEN)
    
    user = get_object_or_404(User, id=user_id)
    
    if request.user.id == user_id:
        return Response({'detail': 'Cannot modify your own account'}, status=status.HTTP_400_BAD_REQUEST)
    serializer = UserUpdateSerializer(user, data=request.data, partial=True)
    if serializer.is_valid():
        updated_user = cast(User, serializer.save())
        return Response({
            'message': 'User updated successfully',
            'user': UserSerializer(updated_user).data
        })
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_user(request, user_id):
    if not request.user.is_admin:
        return Response({'detail': 'Admin access required'}, status=status.HTTP_403_FORBIDDEN)
    
    if request.user.id == user_id:
        return Response({'detail': 'Cannot delete your own account'}, status=status.HTTP_400_BAD_REQUEST)
    
    user = get_object_or_404(User, id=user_id)
    user.delete()
    return Response({'message': 'User deleted successfully'})

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def toggle_admin_status(request, user_id):
    if not request.user.is_admin:
        return Response({'detail': 'Admin access required'}, status=status.HTTP_403_FORBIDDEN)
    
    if request.user.id == user_id:
        return Response({'detail': 'Cannot modify your own admin status'}, status=status.HTTP_400_BAD_REQUEST)
    
    user = get_object_or_404(User, id=user_id)
    user.is_admin = not user.is_admin
    user.save()
    
    action = "promoted to" if user.is_admin else "demoted from"
    return Response({
        'message': f'User {action} admin',
        'user': UserSerializer(user).data
    })
