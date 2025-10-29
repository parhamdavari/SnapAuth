SHELL := /bin/bash
COMPOSE ?= docker compose
SERVICE ?= snapauth
TAIL ?= 100
PORT ?= 8080

.PHONY: help up start stop restart logs ps shell health clean reset creds

help:
	@echo "Setup:"
	@echo "  make up          # regenerate secrets, rebuild, start stack"
	@echo "  make start       # docker compose up -d"
	@echo "  make stop        # docker compose down"
	@echo "  make restart     # stop then start"
	@echo
	@echo "Diagnostics:"
	@echo "  make logs        # tail SERVICE logs (override SERVICE, TAIL)"
	@echo "  make ps          # docker compose ps"
	@echo "  make shell       # docker compose exec SERVICE sh"
	@echo "  make health      # curl SnapAuth health endpoints"
	@echo "  make creds       # display FusionAuth credentials from .env"
	@echo
	@echo "Cleanup:"
	@echo "  make clean       # docker compose down -v --remove-orphans"
	@echo "  make reset       # clean + remove .env and kickstart"

up:
	# Regenerate secrets then rebuild and start stack
	python scripts/bootstrap.py
	$(COMPOSE) up -d --build

start:
	# Start existing containers without rebuilding
	$(COMPOSE) up -d

stop:
	# Stop containers but keep named volumes and generated files
	$(COMPOSE) down

restart: stop start
	# Restart containers without touching volumes

logs:
	# Display logs for selected service (override SERVICE/TAIL)
	$(COMPOSE) logs --tail $(TAIL) $(SERVICE)

ps:
	# Show container status summary
	$(COMPOSE) ps

shell:
	# Open shell inside selected service container
	$(COMPOSE) exec $(SERVICE) sh

health:
	# Check SnapAuth HTTP health endpoints on localhost
	curl --fail http://localhost:$(PORT)/health
	curl --fail http://localhost:$(PORT)/health/jwt-config

clean:
	# Stop stack and remove volumes/orphaned containers
	$(COMPOSE) down -v --remove-orphans

reset: clean
	# Hard reset bootstrap artifacts for fresh setup
	rm -f .env kickstart/kickstart.json

creds:
	# Print stored FusionAuth credentials without modifying files
	python scripts/bootstrap.py --show
