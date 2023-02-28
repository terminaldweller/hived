#!/usr/bin/env sh
set -e
set -x

# sleep 5
curl -k -X GET "https://localhost:8008/crypto/v1/price?name=CAKE&unit=USD"
curl -k -X GET "https://localhost:8008/crypto/v1/pair?one=ETH&two=CAKE&multiplier=4.0"
curl -k -X POST -H "Content-Type: application/json" -d '{"name":"alert1", "expr":"ETH>CAKE"}' https://localhost:8008/crypto/v1/alert

curl -k -X GET -H "Content-Type: application/json" "https://localhost:8008/crypto/v1/alert?key=alert1"
curl -k -X DELETE -H "Content-Type: application/json" "https://localhost:8008/crypto/v1/alert?key=alert1"
curl -k -X POST -H "Content-Type: application/json" -d '{"name":"alert1", "expr":"ETH>CAKE"}' https://localhost:8008/crypto/v1/alert
