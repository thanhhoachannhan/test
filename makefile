
TOKEN_FILE = %temp%\token.txt
REFRESH_TOKEN_FILE = %temp%\refresh_token.txt

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

.PHONY: me
me:
	@for /f "delims=" %%i in ($(TOKEN_FILE)) do curl -s localhost:8000/api/user/me/ -H "Authorization: Bearer %%i"
