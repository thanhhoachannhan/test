from django.urls import path, include, reverse
from django.shortcuts import HttpResponse
from django.core.mail import send_mail
from django.contrib import admin
from django.contrib.auth import get_user_model, tokens
from django.contrib.auth.tokens import default_token_generator

from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView, TokenBlacklistView
from rest_framework import serializers, status, permissions, views, response


def root(request): return HttpResponse('Hello')


class IsSelf(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS: return True
        return request.user == obj

class IsSuperAdmin(permissions.BasePermission):
    def has_permission(self, request, view): return request.user and request.user.is_superuser

class IsManager(permissions.BasePermission):
    def has_permission(self, request, view): return request.user and request.user.is_staff

class IsGuest(permissions.BasePermission):
    def has_permission(self, request, view): return request.user and not (request.user.is_superuser or request.user.is_staff)


class CurrentUser(views.APIView):
    def get_permissions(self):
        return [IsSuperAdmin()] if self.request.method == 'GET' else [IsGuest()]

    class CurrentUserSerializer(serializers.ModelSerializer):
        class Meta:
            model = get_user_model()
            fields = '__all__'
            read_only_fields = ('is_superuser', 'is_staff')
            extra_kwargs = {
                'password': {'write_only': True}
            }

    def get(self, request):
        try:
            serializer = self.CurrentUserSerializer(request.user)
            return response.Response(serializer.data)
        except serializers.ValidationError as ex:
            return response.Response(
                {'error': 'Invalid data', 'details': ex.detail},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as ex:
            return response.Response(
                {'error': str(ex)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class UpdateOwnProfile(views.APIView):
    permission_classes = [IsSelf]

    class UpdateOwnProfileSerializer(serializers.ModelSerializer):
        class Meta:
            model = get_user_model()
            fields = ('email')

    def post(self, request):
        user = request.user
        serializer = self.UpdateOwnProfileSerializer(user, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return response.Response(
                {'message': 'successful'},
                status=status.HTTP_201_CREATED
            )
        return response.Response(serializer.errors)

class TestView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    class TestSerializer(serializers.ModelSerializer):
        class Meta:
            model = get_user_model()
            fields = '__all__'
    def get(self, request):
        serializer = self.TestSerializer(get_user_model().objects.all(), many=True)
        print(serializer.data)
        return response.Response(serializer.data)


class RegisterView(views.APIView):
    class RegisterSerializer(serializers.ModelSerializer):
        password = serializers.CharField(write_only=True, min_length=3)

        class Meta:
            model = get_user_model()
            fields = ('username', 'email', 'password')

        def create(self, validated_data):
            user = get_user_model().objects.create_user(
                username=validated_data['username'],
                email=validated_data['email'],
                password=validated_data['password']
            )
            return user

    def post(self, request):
        serializer = self.RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return response.Response({"detail": "Registration successful"}, status=status.HTTP_201_CREATED)
        return response.Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ChangePasswordView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    class ChangePasswordSerializer(serializers.Serializer):
        current_password = serializers.CharField(required=True)
        new_password = serializers.CharField(required=True)

        def validate_current_password(self, value):
            user = self.context['request'].user
            if not user.check_password(value): raise serializers.ValidationError("Current password is incorrect.")
            return value

        def validate_new_password(self, value):
            if len(value) < 3: raise serializers.ValidationError("New password must be at least 3 characters long.")
            return value

    def post(self, request):
        serializer = self.ChangePasswordSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            user = request.user
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            return response.Response({"detail": "Password has been changed successfully."}, status=status.HTTP_200_OK)
        return response.Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetRequestView(views.APIView):
    def get_permissions(self):
        return [permissions.IsAuthenticated()] if self.request.method == 'GET' else [permissions.AllowAny()]

    class PasswordResetRequestSerializer(serializers.Serializer):
        email = serializers.EmailField()

    def get(self, request):
        email = request.user.email
        if not email: return response.Response({'error': 'Email not found.'}, status=status.HTTP_404_NOT_FOUND)
        token = default_token_generator.make_token(request.user)
        reset_url = reverse('password_reset_confirm')
        reset_link = request.build_absolute_uri(f'{reset_url}?token={token}&email={email}')
        send_mail('Password Reset Request', f'Link reset password: {reset_link}', 'admin@admin.com', [email])
        return response.Response({'message': 'Password reset email sent.'}, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = self.PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = get_user_model().objects.filter(email=email).first()
            if user:
                token = default_token_generator.make_token(user)
                reset_url = reverse('password_reset_confirm')
                reset_link = request.build_absolute_uri(f'{reset_url}?token={token}&email={email}')
                send_mail('Password Reset Request', f'Link reset password: {reset_link}', 'admin@admin.com', [email])
                return response.Response({'message': 'Password reset email sent.'}, status=status.HTTP_200_OK)
            return response.Response({'error': 'Email not found.'}, status=status.HTTP_404_NOT_FOUND)
        return response.Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        

class PasswordResetConfirmView(views.APIView):

    class PasswordResetConfirmSerializer(serializers.Serializer):
        password = serializers.CharField(write_only=True)

    def post(self, request):
        serializer = self.PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            password = serializer.validated_data['password']
            token = request.query_params.get('token')
            email = request.query_params.get('email')
            user = get_user_model().objects.filter(email=email).first()
            if user and default_token_generator.check_token(user, token):
                user.set_password(password)
                user.save()
                return response.Response({'message': 'Password has been reset.'}, status=status.HTTP_200_OK)
            return response.Response({'error': 'Invalid token or email.'}, status=status.HTTP_400_BAD_REQUEST)
        return response.Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DeleteAccountView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request):
        request.user.delete()
        return Response({"detail": "Account has been deleted."}, status=status.HTTP_204_NO_CONTENT)


urlpatterns = [
    path('admin/', admin.site.urls),
    path('', root),
    path('api/', include([
        path('', include('rest_framework.urls', namespace='rest_framework')),
        path('token/', include([
            path('', TokenObtainPairView.as_view(), name='token_obtain_pair'),
            path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
            path('verify/', TokenVerifyView.as_view(), name='token_verify'),
            path('blacklist/', TokenBlacklistView.as_view(), name='token_blacklist'),
        ])),
        path('user/', include([
            path('', TestView.as_view(), name='test'),
            path('register/', RegisterView.as_view(), name='register'),
            path('change-password/', ChangePasswordView.as_view(), name='change_password'),
            path('password-reset/', PasswordResetRequestView.as_view(), name='password_reset_request'),
            path('password-reset/confirm/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
            path('delete-account/', DeleteAccountView.as_view(), name='delete_account'),
            path('me/', include([
                path('', CurrentUser.as_view(), name='current_user'),
                path('update/', UpdateOwnProfile.as_view(), name='update_own_profile'),
            ])),
        ]))
    ])),
]