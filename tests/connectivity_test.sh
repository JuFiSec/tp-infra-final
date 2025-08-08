#!/bin/bash
# tests/connectivity_test.sh
# Script de test de connectivité des services

echo "🧪 Test de connectivité de l'infrastructure"
echo "=========================================="

# Configuration
BASE_URL="http://localhost"
SERVICES=(
    "80:WAF ModSecurity"
    "8001:Kong Admin API"
    "5678:n8n Workflows"
    "8080:Traefik Dashboard"
    "9090:Prometheus"
    "3000:Grafana"
    "5601:Kibana"
    "9200:Elasticsearch"
    "8081:cAdvisor"
)

# Fonction de test
test_service() {
    local port=$1
    local name=$2
    
    echo -n "Testing $name (port $port)... "
    
    if curl -s -I "$BASE_URL:$port" > /dev/null 2>&1; then
        echo " OK"
        return 0
    else
        echo "❌ FAILED"
        return 1
    fi
}

# Tests
failed=0
total=${#SERVICES[@]}

for service in "${SERVICES[@]}"; do
    port=$(echo $service | cut -d: -f1)
    name=$(echo $service | cut -d: -f2)
    
    if ! test_service $port "$name"; then
        ((failed++))
    fi
done

# Résumé
echo ""
echo "=========================================="
echo "Résultats: $((total - failed))/$total services OK"

if [ $failed -eq 0 ]; then
    echo "🎉 Tous les services sont accessibles!"
    exit 0
else
    echo "⚠️  $failed service(s) en échec"
    exit 1
fi

