.PHONY: keys build up down logs test browser

# Generate the secrets for .env
keys:
	@echo "XLOGIN_API_KEYS=$$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')"
	@echo "XLOGIN_ENCRYPTION_KEYS=$$(python3 -c 'from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())')"
	@echo "XLOGIN_WEBHOOK_SECRET=$$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')"

browser:
	docker build -t xlogin-browser:latest ./login-browser

build: browser
	docker compose build

up: build
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f xlogin

test:
	python3 -m pytest -q
