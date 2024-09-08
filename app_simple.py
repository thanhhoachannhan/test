import os, sys, pathlib, django.core.management as exec
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'app')
if __name__ == '__main__': exec.execute_from_command_line(sys.argv)
BASE_DIR = pathlib.Path(__file__).resolve().parent
SECRET_KEY = 'DJANGO'
DEBUG = True
ROOT_URLCONF = 'urls'
STATIC_URL = 'static/'
INSTALLED_APPS = [f'django.contrib.{app}' for app in 'admin,auth,contenttypes,messages,staticfiles'.split(',')]
DATABASES = {'default':{'ENGINE':'django.db.backends.sqlite3','NAME':'db.sqlite3'}}
MIDDLEWARE = [f'django.contrib.{a}.middleware.{b}Middleware' for a,b in [('auth','Authentication'),('sessions','Session'),('messages','Message')]]
TEMPLATES = [{
    'BACKEND': 'django.template.backends.django.DjangoTemplates',
    'DIRS': [BASE_DIR],
    'APP_DIRS': True,
    'OPTIONS': {'context_processors': [f'django.contrib.{x}.context_processors.{x}' for x in ['auth','messages']]}
}]