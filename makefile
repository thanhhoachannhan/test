
TOKEN_FILE = %temp%\token.txt
REFRESH_TOKEN_FILE = %temp%\refresh_token.txt

MANAGE_FILE = app

.PHONY: init
init:
	python ${MANAGE_FILE}.py migrate
	python ${MANAGE_FILE}.py shell -c "from django.contrib.auth import get_user_model; get_user_model().objects.filter(username='admin').exists() or get_user_model().objects.create_superuser('admin', 'admin@admin.com', 'admin')"

.PHONY: server
server:
	python ${MANAGE_FILE}.py runserver

.PHONY: root
root:
	curl localhost:8000

.PHONY: token
token:
	@curl -s -X POST -d "username=admin&password=admin" http://localhost:8000/api/token/ \
	| python -c "import sys, json; print(json.load(sys.stdin)['access'])" > $(TOKEN_FILE)
	@curl -s -X POST -d "username=admin&password=admin" http://localhost:8000/api/token/ \
	| python -c "import sys, json; print(json.load(sys.stdin)['refresh'])" > $(REFRESH_TOKEN_FILE)
	curl localhost:8000/api/token/ -d "username=admin&password=admin"

.PHONY: refresh
refresh:
	@for /f "delims=" %%i in ($(REFRESH_TOKEN_FILE)) do curl localhost:8000/api/token/refresh/ -d "refresh=%%i"

.PHONY: verify
verify:
	@for /f "delims=" %%i in ($(TOKEN_FILE)) do curl localhost:8000/api/token/verify/ -d "token=%%i"

.PHONY: blacklist
blacklist:
	@for /f "delims=" %%i in ($(REFRESH_TOKEN_FILE)) do curl localhost:8000/api/token/blacklist/ -d "refresh=%%i"
	@for /f "delims=" %%i in ($(REFRESH_TOKEN_FILE)) do curl localhost:8000/api/token/refresh/ -d "refresh=%%i"

.PHONY: user
user:
	@for /f "delims=" %%i in ($(TOKEN_FILE)) do curl -s localhost:8000/api/user/ -H "Authorization: Bearer %%i"

.PHONY: user1
user1:
	@for /f "delims=" %%i in ($(TOKEN_FILE)) do curl -s localhost:8000/api/user/1/ -H "Authorization: Bearer %%i"

.PHONY: register
register:
	curl localhost:8000/api/user/register/ -d "email=test@test.test&username=test&password=test"

.PHONY: email_verification_get
email_verification_get:
	@for /f "delims=" %%i in ($(TOKEN_FILE)) do curl -s localhost:8000/api/user/email_verification/ -H "Authorization: Bearer %%i"

.PHONY: email_verification_post
email_verification_post:
	curl localhost:8000/api/user/email_verification/ -d "email=admin@admin.com"

.PHONY: change_password
change_password:
	@for /f "delims=" %%i in ($(TOKEN_FILE)) do curl -s localhost:8000/api/user/change_password/ -H "Authorization: Bearer %%i" -d "current_password=admin&new_password=admin"

.PHONY: password_reset_get
password_reset_get:
	@for /f "delims=" %%i in ($(TOKEN_FILE)) do curl -s localhost:8000/api/user/password_reset/ -H "Authorization: Bearer %%i"

.PHONY: password_reset_post
password_reset_post:
	curl localhost:8000/api/user/password_reset/ -d "email=admin@admin.com"

.PHONY: me
me:
	@for /f "delims=" %%i in ($(TOKEN_FILE)) do curl -s localhost:8000/api/user/me/ -H "Authorization: Bearer %%i"

