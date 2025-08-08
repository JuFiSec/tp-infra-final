```mermaid
graph TB
    subgraph "🌐 Internet / Utilisateurs"
        Users[👥 Utilisateurs]
    end
    
    subgraph "🛡️ COUCHE SÉCURITÉ - Amine"
        subgraph "amine-security/"
            WAF[🔥 ModSecurity WAF<br/>📍 Port 80/443<br/>🔒 OWASP Rules]
            Kong[🚪 Kong Gateway<br/>📍 Port 8000/8001<br/>🔑 Auth + Rate Limiting]
            Suricata[👁️ Suricata IDS<br/>🔍 Network Analysis<br/>⚠️ Threat Detection]
            KongDB[(🗄️ Kong Database<br/>PostgreSQL)]
        end
    end
    
    subgraph "🖥️ COUCHE APPLICATIONS - Fieni"
        subgraph "fieni-app/"
            Traefik[🔄 Traefik Proxy<br/>📍 Port 8080<br/>🔐 SSL Auto]
            N8N[⚡ n8n Workflows<br/>📍 Port 5678<br/>🤖 Automation]
            PostgresMain[(🗄️ PostgreSQL Main<br/>n8n Database)]
            Redis[(💾 Redis Cache<br/>Sessions + Queue)]
        end
    end
    
    subgraph "📊 COUCHE MONITORING - Khaoutar"
        subgraph "khaoutar-monitoring/"
            Prometheus[📈 Prometheus<br/>📍 Port 9090<br/>📊 Metrics Collection]
            Grafana[📱 Grafana<br/>📍 Port 3000<br/>🎛️ Dashboards]
            
            subgraph "ELK Stack - SIEM"
                Elasticsearch[(🔍 Elasticsearch<br/>📍 Port 9200<br/>📚 Log Storage)]
                Logstash[🔄 Logstash<br/>📍 Port 12201<br/>🛠️ Log Processing]
                Kibana[🖥️ Kibana<br/>📍 Port 5601<br/>🔎 Log Analysis]
            end
            
            subgraph "Exporters"
                PgExporter[📊 Postgres Exporter]
                RedisExporter[📊 Redis Exporter]
                NodeExporter[📊 Node Exporter]
                CAdvisor[📊 cAdvisor]
            end
        end
    end
    
    subgraph "🔗 RÉSEAUX DOCKER"
        Frontend[🌐 frontend<br/>172.20.0.0/24]
        Security[🛡️ security<br/>172.23.0.0/24]
        Backend[🖥️ backend<br/>172.21.0.0/24]
        Monitoring[📊 monitoring<br/>172.22.0.0/24]
    end
    
    %% Flux principal utilisateur
    Users -->|HTTPS/HTTP| WAF
    WAF -->|Filtrage| Kong
    Kong -->|Routing| Traefik
    Kong -->|API Calls| N8N
    
    %% Dépendances applications
    N8N --> PostgresMain
    N8N --> Redis
    Kong --> KongDB
    
    %% Flux de logs (SIEM)
    WAF -.->|GELF Logs| Logstash
    Kong -.->|GELF Logs| Logstash
    N8N -.->|GELF Logs| Logstash
    Traefik -.->|GELF Logs| Logstash
    Suricata -.->|JSON Logs| Logstash
    
    Logstash -->|Parsed| Elasticsearch
    Elasticsearch --> Kibana
    
    %% Flux de métriques (Monitoring)
    PgExporter -.->|Metrics| Prometheus
    RedisExporter -.->|Metrics| Prometheus
    NodeExporter -.->|Metrics| Prometheus
    CAdvisor -.->|Metrics| Prometheus
    Kong -.->|Metrics| Prometheus
    
    Prometheus --> Grafana
    
    %% Analyse sécurité
    Suricata -.->|Network Traffic| WAF
    Suricata -.->|Alerts| Elasticsearch
    
    %% Styles
    classDef security fill:#ff6b6b,stroke:#ff4757,stroke-width:2px,color:#fff
    classDef application fill:#4ecdc4,stroke:#00d2d3,stroke-width:2px,color:#fff
    classDef monitoring fill:#45b7d1,stroke:#0097e6,stroke-width:2px,color:#fff
    classDef database fill:#f9ca24,stroke:#f0932b,stroke-width:2px,color:#000
    classDef network fill:#6c5ce7,stroke:#5f3dc4,stroke-width:2px,color:#fff
    
    class WAF,Kong,Suricata,KongDB security
    class Traefik,N8N,PostgresMain,Redis application
    class Prometheus,Grafana,Elasticsearch,Logstash,Kibana,PgExporter,RedisExporter,NodeExporter,CAdvisor monitoring
    class Frontend,Security,Backend,Monitoring network
