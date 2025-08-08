#!/bin/bash
# tests/ids_detection.sh
# Script de test de détection IDS Suricata

echo "🕵️ Test de détection IDS Suricata"
echo "=================================="

TARGET="localhost"

echo "Generating suspicious network traffic..."

echo -n "Port scanning... "
if command -v nmap >/dev/null 2>&1; then
    nmap -sS -p 1-100 $TARGET >/dev/null 2>&1
    echo "✅ Done"
else
    echo "⚠️  nmap not available"
fi

echo -n "SYN flood simulation... "
if command -v hping3 >/dev/null 2>&1; then
    hping3 -S -p 80 -c 100 $TARGET >/dev/null 2>&1
    echo "✅ Done"
else
    echo "⚠️  hping3 not available"
fi

echo -n "HTTP flood... "
for i in {1..50}; do
    curl -s "$TARGET" >/dev/null 2>&1 &
done
wait
echo "✅ Done"

echo ""
echo "🔍 Check Suricata logs:"
echo "docker-compose logs suricata"
echo ""
echo "🔍 Check alerts in Kibana:"
echo "http://localhost:5601"

