#!/usr/bin/env sh
set -e
set -x

sleep 5
curl -X GET http://127.0.0.1:8008/price?name=CAKE&unit=USD
curl -X GET http://127.0.0.1:8008/pair?one=ETH&two=CAKE&multiplier=4.0
curl -X POST -H "Content-Type: application/json" -d '{"name":"alert1", "expr":"ETH>CAKE"}' http://127.0.0.1:8008/addalert
#curl -X POST 
