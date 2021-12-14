#!/usr/bin/env sh
set -ex

export $(cat /run/secrets/tg_bot_token)
export $(cat /run/secrets/ch_api_key)
export $(cat /run/secrets/ch_api_secret)

"/hived/hived" "$@"
