#!/usr/bin/env sh
set -e
set -x

# sleep 5
curl -k -X GET https://localhost:8008/crypto/price?name=CAKE&unit=USD
curl -k -X GET https://localhost:8008/crypto/pair?one=ETH&two=CAKE&multiplier=4.0
curl -k -X POST -H "Content-Type: application/json" -d '{"name":"alert1", "expr":"ETH>CAKE"}' https://localhost:8008/crypto/alert

curl -X GET -H "Content-Type: application/json" "https://api.terminaldweller.com/crypto/alert?key=alert10"
curl -X DELETE -H "Content-Type: application/json" "https://api.terminaldweller.com/crypto/alert?key=alert10"
curl -X POST -H "Content-Type: application/json" -d '{"name":"alert1", "expr":"ETH>CAKE"}' https://api.terminaldweller.com/crypto/alert
