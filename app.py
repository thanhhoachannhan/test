import os, sys, pathlib, signal, shutil, django
from django.core.management import execute_from_command_line
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'app')
BASE_DIR = pathlib.Path(__file__).resolve().parent
SECRET_KEY = 'django'
DEBUG = True
ALLOWED_HOSTS = ['*']
STATIC_URL = 'static/'
ROOT_URLCONF = 'urls'
class Config(django.apps.AppConfig): name = 'core'; default_auto_field = 'django.db.models.BigAutoField'
INSTALLED_APPS = [f'django.contrib.{app}' for app in 'admin,auth,contenttypes,sessions,messages,staticfiles'.split(',')] + ['app.Config', 'rest_framework']
DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': 'db.sqlite3'}}
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
]
CONTEXT_PROCESSORS = [
    'django.template.context_processors.debug',
    'django.template.context_processors.request',
    'django.contrib.auth.context_processors.auth',
    'django.contrib.messages.context_processors.messages',
]
TEMPLATES = [{
    'BACKEND': 'django.template.backends.django.DjangoTemplates',
    'DIRS': [os.path.join(BASE_DIR, 'templates')],
    'APP_DIRS': True,
    'OPTIONS': {'context_processors': CONTEXT_PROCESSORS}
}]
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': ['rest_framework_simplejwt.authentication.JWTAuthentication'],
    'DEFAULT_PERMISSION_CLASSES': ['rest_framework.permissions.IsAuthenticated'],
}
def handle_signal(sig, frame):
    for module in '__pycache__,core,urls.py,models.py,api.py'.split(','):
        shutil.rmtree(module, ignore_errors=True)
        if os.path.exists(module): os.remove(module)
    sys.exit(0)
signal.signal(signal.SIGINT, handle_signal)
if __name__ == '__main__': execute_from_command_line(sys.argv)
for cop in 'models,urls,api'.split(','):
    with open('app.py', 'r') as x: lines = x.readlines()
    for idx, line in enumerate(lines):
        if f'# @{cop}' in line: s_idx = idx + 2
        if f'# @end_{cop}' in line: e_idx = idx - 1
    if s_idx is not None and e_idx is not None:
        if not os.path.exists('core'): os.mkdir('core')
        with open(f'core/{cop}.py' if cop == 'models' else f'{cop}.py', 'w') as y: y.writelines(lines[s_idx:e_idx])
# @urls
"""
from django.urls import path, include
from django.contrib import admin

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('api'))
]
"""
# @end_urls

# @models
"""
from django.db import models

class Poll(models.Model):
    name = models.TextField()
"""
# @end_models

# @api
"""
from django.urls import path, include
from django.contrib.auth import get_user_model

from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework import serializers, status, permissions, views, response
from rest_framework import permissions

from core.models import *


class IsSelf(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        return request.user == obj


class IsSuperAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_superuser


class IsManager(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_staff


class IsGuest(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and not (request.user.is_superuser or request.user.is_staff)


class CurrentUser(views.APIView):
    # permission_classes = [IsManager]

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
    class TestSerializer(serializers.ModelSerializer):
        class Meta:
            model = Poll
            fields = '__all__'
    def get(self, request):
        serializer = self.TestSerializer()
        return response.Response(serializer.data)
    
urlpatterns = [
    path('', TestView.as_view()),
    path('token/', include([
        path('', TokenObtainPairView.as_view(), name='token_obtain_pair'),
        path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    ])),
    path('user/', include([
        path('me/', include([
            path('', CurrentUser.as_view(), name='current_user'),
            path('update/', UpdateOwnProfile.as_view(), name='update_own_profile'),
        ])),
    ]))
]
"""
# @end_api