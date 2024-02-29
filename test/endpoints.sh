#!/usr/bin/env sh
set -e
set -x

curl -k -X GET "https://localhost:10008/crypto/v1/price?name=PEPE&unit=USD"
curl -k -X GET "https://localhost:10008/crypto/v1/pair?one=ETH&two=CAKE&multiplier=4.0"
curl -k -X POST -H "Content-Type: application/json" -d '{"name":"alert1", "expr":"ETH>CAKE"}' https://localhost:10008/crypto/v1/alert

# alert
curl -k -X GET -H "Content-Type: application/json" "https://localhost:10008/crypto/v1/alert?key=alert1"
curl -k -X DELETE -H "Content-Type: application/json" "https://localhost:10008/crypto/v1/alert?key=alert1"
curl -k -X POST -H "Content-Type: application/json" -d '{"name":"alert1", "expr":"ETH>CAKE"}' https://localhost:10008/crypto/v1/alert

# ticker
curl -k -X POST -H "Content-Type: application/json" -d '{"name":"ETH"}' https://localhost:10008/crypto/v1/ticker
curl -k -X POST -H "Content-Type: application/json" -d '{"name":"BTC"}' https://localhost:10008/crypto/v1/ticker
curl -k -X POST -H "Content-Type: application/json" -d '{"name":"XMR"}' https://localhost:10008/crypto/v1/ticker
curl -k -X POST -H "Content-Type: application/json" -d '{"name":"STX"}' https://localhost:10008/crypto/v1/ticker
curl -k -X POST -H "Content-Type: application/json" -d '{"name":"LINK"}' https://localhost:10008/crypto/v1/ticker
curl -k -X POST -H "Content-Type: application/json" -d '{"name":"PEPE"}' https://localhost:10008/crypto/v1/ticker
curl -k -X GET -H "Content-Type: application/json" https://localhost:10008/crypto/v1/ticker?key=ETH
curl -k -X DELETE -H "Content-Type: application/json" https://localhost:10008/crypto/v1/ticker?key=ETH
