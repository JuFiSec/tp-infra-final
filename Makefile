## 🔧 **Makefile adapté à votre structure**

```makefile
# Commandes pour respecter votre organisation d'équipe

start: ## Démarre l'infrastructure intégrée
	@echo "🚀 Démarrage de l'infrastructure complète"
	@echo "🖥️  Stack Fieni (Applications)"
	@echo "📊 Stack Khaoutar (Monitoring)"  
	@echo "🛡️  Stack Amine (Sécurité)"
	@docker-compose up -d

start-fieni: ## Démarre uniquement la stack de Fieni
	@echo "🖥️ Démarrage stack Applications (Fieni)"
	@cd fieni-app && docker-compose up -d

start-khaoutar: ## Démarre uniquement la stack de Khaoutar  
	@echo "📊 Démarrage stack Monitoring (Khaoutar)"
	@cd khaoutar-monitoring && docker-compose up -d

start-amine: ## Démarre uniquement la stack d'Amine
	@echo "🛡️ Démarrage stack Sécurité (Amine)"
	@cd amine-security && docker-compose up -d

dev-fieni: ## Mode développement pour Fieni
	@cd fieni-app && docker-compose up --build

dev-khaoutar: ## Mode développement pour Khaoutar
	@cd khaoutar-monitoring && docker-compose up --build

dev-amine: ## Mode développement pour Amine  
	@cd amine-security && docker-compose up --build