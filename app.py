import os,sys,pathlib,django.core.management as exec
os.environ.setdefault('DJANGO_SETTINGS_MODULE','app')
if __name__ == '__main__': exec.execute_from_command_line(sys.argv)
BASE=pathlib.Path(__file__).resolve().parent;SECRET_KEY='X';DEBUG=True;ROOT_URLCONF='urls';STATIC_URL='static/'
DATABASES={'default':{'ENGINE':'django.db.backends.sqlite3','NAME':'db.sqlite3'}}
INSTALLED_APPS=[f'django.contrib.{x}' for x in 'admin,auth,sessions,contenttypes,messages,staticfiles'.split(',')]+['rest_framework','rest_framework_simplejwt.token_blacklist']
MIDDLEWARE=[f'django.contrib.{a}.middleware.{b}Middleware' for a,b in [('sessions','Session'),('auth','Authentication'),('messages','Message')]]
TEMPLATES=[{'BACKEND':'django.template.backends.django.DjangoTemplates','DIRS':[BASE],'APP_DIRS':True,'OPTIONS':{'context_processors':[f'django.contrib.{x}.context_processors.{x}' for x in ['auth','messages']]}}]
REST_FRAMEWORK = {'DEFAULT_AUTHENTICATION_CLASSES': ['rest_framework_simplejwt.authentication.JWTAuthentication']}
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
SILENCED_SYSTEM_CHECKS=['admin.W411']
import sys,signal,shutil; signal.signal(signal.SIGINT, lambda sig, frame: (shutil.rmtree('__pycache__', ignore_errors=True), sys.exit(0)))
