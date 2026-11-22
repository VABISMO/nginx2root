# nginx2root lab — common tasks. See README.md for details.
PYTHON  ?= python3
COMPOSE ?= docker compose

.PHONY: up down build certs check verify lint clean help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

certs: ## Generate the self-signed lab certificate (idempotent)
	$(PYTHON) tools/gen_certs.py

build: certs ## Build both images
	$(COMPOSE) build

up: certs ## Start the vulnerable (8443) and patched (9443) targets
	$(COMPOSE) up -d --build --wait

down: ## Stop and remove the lab
	$(COMPOSE) down -v --remove-orphans

check: ## One-off check against the vulnerable container (expects exit 2)
	$(PYTHON) tools/check_exposure.py --host localhost --port 8443 \
		--cafile lab/certs/server.crt; \
	rc=$$?; \
	echo "checker exited $$rc (2 = EXPOSED, as expected for nginx/1.31.8)"; \
	test $$rc -eq 2

verify: ## Assert A/B behaviour end to end (the CI gate)
	$(PYTHON) tools/verify_lab.py

lint: ## Static checks: ruff, byte-compile, selftest, CLI smoke tests
	ruff check tools/
	$(PYTHON) -m compileall -q tools
	cd tools && $(PYTHON) selftest.py
	$(PYTHON) tools/check_exposure.py --help > /dev/null
	$(PYTHON) tools/check_exposure.py --version

clean: down ## Remove generated certificates and caches
	rm -rf lab/certs tools/__pycache__ .ruff_cache
