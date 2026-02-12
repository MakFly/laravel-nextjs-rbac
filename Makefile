# ==============================================================================
# Laravel + Next.js RBAC - Makefile
# ==============================================================================
#
# Utilisation :
#   make              → Affiche cette aide
#   make <commande>   → Exécute la commande
#
# Prérequis :
#   - bun (https://bun.sh)
#   - php >= 8.2
#   - composer
#   - docker (optionnel, pour les services)
#
# ==============================================================================

.PHONY: help install setup dev dev-web dev-vue dev-api build test lint clean \
        docker-up docker-down docker-logs \
        db-migrate db-seed db-reset \
        api-install api-test api-tinker

# Couleurs pour les messages
CYAN    := \033[36m
GREEN   := \033[32m
YELLOW  := \033[33m
RESET   := \033[0m

# ==============================================================================
# COMMANDES PRINCIPALES
# ==============================================================================

## help : Affiche cette aide (commande par défaut)
help:
	@echo ""
	@echo "$(CYAN)╔══════════════════════════════════════════════════════════════╗$(RESET)"
	@echo "$(CYAN)║         Laravel + Next.js RBAC - Commandes disponibles        ║$(RESET)"
	@echo "$(CYAN)╚══════════════════════════════════════════════════════════════╝$(RESET)"
	@echo ""
	@echo "$(GREEN)Installation & Setup$(RESET)"
	@echo "  make install         → Installe les dépendances (bun + composer)"
	@echo "  make setup           → Setup complet (install + env + db)"
	@echo ""
	@echo "$(GREEN)Développement$(RESET)"
	@echo "  make dev             → Lance web + api en parallèle"
	@echo "  make dev-web         → Lance uniquement Next.js (port 3001)"
	@echo "  make dev-vue         → Lance uniquement Vue.js (port 5173)"
	@echo "  make dev-api         → Lance uniquement Laravel (port 8000)"
	@echo ""
	@echo "$(GREEN)Build & Test$(RESET)"
	@echo "  make build           → Build production (tous les apps)"
	@echo "  make test            → Lance les tests (web + api)"
	@echo "  make lint            → Vérifie le code (lint)"
	@echo ""
	@echo "$(GREEN)Base de données$(RESET)"
	@echo "  make db-migrate      → Exécute les migrations"
	@echo "  make db-seed         → Exécute les seeders"
	@echo "  make db-reset        → Reset complet (migrate:fresh + seed)"
	@echo ""
	@echo "$(GREEN)Docker (services)$(RESET)"
	@echo "  make docker-up       → Démarre postgres, redis, mailpit"
	@echo "  make docker-down     → Arrête les containers"
	@echo "  make docker-logs     → Affiche les logs des containers"
	@echo ""
	@echo "$(GREEN)Nettoyage$(RESET)"
	@echo "  make clean           → Nettoie les builds et caches"
	@echo ""
	@echo "$(YELLOW)Astuce :$(RESET) Tape 'make <tab>' pour l'autocomplétion"
	@echo ""

# ==============================================================================
# INSTALLATION
# ==============================================================================

## install : Installe toutes les dépendances (bun + composer)
install:
	@echo "$(CYAN)→ Installation des dépendances Node/Bun...$(RESET)"
	bun install
	@echo "$(CYAN)→ Installation des dépendances PHP/Composer...$(RESET)"
	cd apps/api && composer install
	@echo "$(GREEN)✓ Dépendances installées$(RESET)"

## setup : Setup complet du projet (install + env + db)
setup: install
	@echo "$(CYAN)→ Configuration de l'environnement...$(RESET)"
	@if [ ! -f apps/api/.env ]; then \
		cp apps/api/.env.example apps/api/.env; \
		cd apps/api && php artisan key:generate; \
	fi
	@echo "$(CYAN)→ Migration de la base de données...$(RESET)"
	$(MAKE) db-migrate
	@echo "$(GREEN)✓ Setup terminé ! Lance 'make dev' pour démarrer.$(RESET)"

# ==============================================================================
# DÉVELOPPEMENT
# ==============================================================================

## dev : Lance le serveur de développement (web + api)
dev:
	@echo "$(CYAN)→ Démarrage en mode développement...$(RESET)"
	@bun run dev

## dev-web : Lance uniquement Next.js (port 3001)
dev-web:
	@echo "$(CYAN)→ Démarrage de Next.js sur http://localhost:3001$(RESET)"
	cd apps/web && bun run dev

## dev-vue : Lance uniquement Vue.js (port 5173)
dev-vue:
	@echo "$(CYAN)→ Démarrage de Vue.js sur http://localhost:5173$(RESET)"
	cd apps/web-vuejs && bun run dev

## dev-api : Lance uniquement Laravel (port 8000)
dev-api:
	@echo "$(CYAN)→ Démarrage de Laravel sur http://localhost:8000$(RESET)"
	cd apps/api && php artisan serve --port=8000

# ==============================================================================
# BUILD
# ==============================================================================

## build : Build production de tous les apps
build:
	@echo "$(CYAN)→ Build production...$(RESET)"
	bun run build
	@echo "$(GREEN)✓ Build terminé$(RESET)"

## prod : Build et démarre en mode production
prod:
	@echo "$(CYAN)→ Mode production...$(RESET)"
	bun run prod

# ==============================================================================
# TESTS & LINT
# ==============================================================================

## test : Lance tous les tests (web + api)
test:
	@echo "$(CYAN)→ Tests Next.js...$(RESET)"
	cd apps/web && bun run test 2>/dev/null || true
	@echo "$(CYAN)→ Tests Laravel...$(RESET)"
	cd apps/api && composer test

## lint : Vérifie la qualité du code
lint:
	@echo "$(CYAN)→ Linting...$(RESET)"
	bun run lint

## format : Formate le code avec Prettier
format:
	@echo "$(CYAN)→ Formatage du code...$(RESET)"
	bun run format

# ==============================================================================
# BASE DE DONNÉES
# ==============================================================================

## db-migrate : Exécute les migrations Laravel
db-migrate:
	@echo "$(CYAN)→ Exécution des migrations...$(RESET)"
	cd apps/api && php artisan migrate

## db-seed : Exécute les seeders Laravel
db-seed:
	@echo "$(CYAN)→ Exécution des seeders...$(RESET)"
	cd apps/api && php artisan db:seed

## db-reset : Reset complet de la base (migrate:fresh + seed)
db-reset:
	@echo "$(YELLOW)→ Reset de la base de données...$(RESET)"
	cd apps/api && php artisan migrate:fresh --seed
	@echo "$(GREEN)✓ Base de données réinitialisée$(RESET)"

# ==============================================================================
# API SPÉCIFIQUE
# ==============================================================================

## api-tinker : Lance le REPL Laravel Tinker
api-tinker:
	cd apps/api && php artisan tinker

## api-routes : Affiche les routes Laravel
api-routes:
	cd apps/api && php artisan route:list

## api-clear : Clear les caches Laravel
api-clear:
	@echo "$(CYAN)→ Clear des caches Laravel...$(RESET)"
	cd apps/api && php artisan cache:clear
	cd apps/api && php artisan config:clear
	cd apps/api && php artisan route:clear
	cd apps/api && php artisan view:clear
	@echo "$(GREEN)✓ Caches nettoyés$(RESET)"

# ==============================================================================
# DOCKER
# ==============================================================================

## docker-up : Démarre les containers (postgres, redis, mailpit)
docker-up:
	@echo "$(CYAN)→ Démarrage des containers Docker...$(RESET)"
	docker-compose up -d
	@echo "$(GREEN)✓ Services démarrés :$(RESET)"
	@echo "  • PostgreSQL : localhost:5432"
	@echo "  • Redis      : localhost:6379"
	@echo "  • Mailpit    : http://localhost:8025"

## docker-down : Arrête les containers
docker-down:
	@echo "$(CYAN)→ Arrêt des containers Docker...$(RESET)"
	docker-compose down

## docker-logs : Affiche les logs des containers
docker-logs:
	docker-compose logs -f

## docker-reset : Reset complet des containers et volumes
docker-reset:
	@echo "$(YELLOW)→ Reset complet des containers...$(RESET)"
	docker-compose down -v --remove-orphans
	docker-compose up -d

# ==============================================================================
# NETTOYAGE
# ==============================================================================

## clean : Nettoie les builds, caches et node_modules
clean:
	@echo "$(CYAN)→ Nettoyage des builds Next.js...$(RESET)"
	rm -rf apps/web/.next
	@echo "$(CYAN)→ Nettoyage des builds Vue.js...$(RESET)"
	rm -rf apps/web-vuejs/dist
	@echo "$(CYAN)→ Nettoyage des caches Turbo...$(RESET)"
	rm -rf .turbo
	@echo "$(CYAN)→ Nettoyage des caches Laravel...$(RESET)"
	cd apps/api && php artisan clear-compiled 2>/dev/null || true
	@echo "$(GREEN)✓ Nettoyage terminé$(RESET)"

## clean-all : Nettoyage complet (inclut node_modules)
clean-all: clean
	@echo "$(YELLOW)→ Suppression de node_modules...$(RESET)"
	rm -rf node_modules apps/*/node_modules packages/*/node_modules
	rm -rf bun.lock
	@echo "$(YELLOW)→ Suppression de vendor...$(RESET)"
	rm -rf apps/api/vendor
	@echo "$(GREEN)✓ Nettoyage complet terminé. Lance 'make install' pour réinstaller.$(RESET)"

# ==============================================================================
# DIVERS
# ==============================================================================

## env-check : Vérifie que les fichiers .env existent
env-check:
	@if [ ! -f apps/api/.env ]; then \
		echo "$(YELLOW)⚠ apps/api/.env manquant. Copie depuis .env.example...$(RESET)"; \
		cp apps/api/.env.example apps/api/.env; \
		cd apps/api && php artisan key:generate; \
	fi
	@if [ ! -f apps/web/.env.local ]; then \
		echo "$(YELLOW)⚠ apps/web/.env.local manquant. Création...$(RESET)"; \
		touch apps/web/.env.local; \
	fi
	@echo "$(GREEN)✓ Environnement configuré$(RESET)"

## info : Affiche les informations du projet
info:
	@echo "$(CYAN)Informations du projet$(RESET)"
	@echo "========================"
	@echo "PHP        : $$(php -r 'echo PHP_VERSION;' 2>/dev/null || echo 'non installé')"
	@echo "Bun        : $$(bun --version 2>/dev/null || echo 'non installé')"
	@echo "Composer   : $$(composer --version 2>/dev/null | head -1 || echo 'non installé')"
	@echo "Docker     : $$(docker --version 2>/dev/null || echo 'non installé')"
	@echo ""
	@echo "Structure :"
	@echo "  • apps/web        → Next.js (port 3001)"
	@echo "  • apps/web-vuejs  → Vue.js  (port 5173)"
	@echo "  • apps/api        → Laravel (port 8000)"
	@echo "  • packages/       → Packages partagés"
