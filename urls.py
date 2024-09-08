from django.urls import path, include
from django.shortcuts import HttpResponse
from django.contrib import admin
from django.contrib.auth import get_user_model

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
            path('me/', include([
                path('', CurrentUser.as_view(), name='current_user'),
                path('update/', UpdateOwnProfile.as_view(), name='update_own_profile'),
            ])),
        ]))
    ])),
]