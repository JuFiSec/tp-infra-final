# 🛡️ Stack Kong + Konga + PostgreSQL + ModSecurity + Suricata

Ce projet met en place une stack complète de gestion d’API avec **Kong**, son interface web **Konga**, une base de données **PostgreSQL**, un pare-feu applicatif **ModSecurity**, et un IDS/IPS **Suricata**. L’objectif est de créer une passerelle d’API sécurisée et facilement administrable.

---

## 📦 Services inclus

| Service       | Description                                          | Port(s) Exposés |
|---------------|------------------------------------------------------|------------------|
| **PostgreSQL** | Base de données utilisée par Kong et Konga          | 5432             |
| **Adminer**    | Interface web simple pour gérer PostgreSQL          | 9080             |
| **Kong**       | API Gateway                                          | 8000 (HTTP), 8443 (HTTPS), 8001 (Admin) |
| **Konga**      | Interface d’administration de Kong                  | 1337             |
| **ModSecurity**| Pare-feu applicatif WAF (connecté à Kong)          | 80               |
| **Suricata**   | IDS/IPS pour surveiller le trafic réseau            | N/A (mode host)  |

---

## 🚀 Démarrage rapide

### 1. Cloner ce dépôt (ou coller les fichiers nécessaires)
```bash
git clone <URL_DU_DEPOT>
cd <nom_du_projet>


2. Lancer la stack
bash
Copier le code
docker-compose up -d

Identifiants par défaut
Service	Utilisateur	Mot de passe
PostgreSQL	kong	kong
Konga	À configurer au premier lancement

🌐 Accès aux interfaces
Adminer (gestion DB) : http://localhost:9080

Konga (GUI Kong) : http://localhost:1337

Kong Admin API : http://localhost:8001

Kong Proxy : http://localhost:8000

ModSecurity WAF : http://localhost

Arrêter la stack

docker-compose down


