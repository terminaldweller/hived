#!/bin/sh
set -ex

export "$(cat /run/secrets/tg_bot_token)"

"/hived/hived" "$@"
