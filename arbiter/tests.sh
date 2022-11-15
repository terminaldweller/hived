#!/usr/bin/env sh

curl -k -X GET "https://localhost:8009/crypto/v1/arb/gecko?name=ethereum&unit=usd"
curl -k -X GET "https://localhost:8009/crypto/v1/arb/coincap?name=ethereum"
