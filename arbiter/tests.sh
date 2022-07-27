#!/usr/bin/env sh

curl -k -X GET "https://localhost:8009/arb/gecko?name=ethereum&unit=usd"
curl -k -X GET "https://localhost:8009/arb/coincap?name=ethereum"
