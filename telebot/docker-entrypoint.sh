#!/usr/bin/env sh
set -ex

export $(cat /run/secrets/tg_bot_token)

"/telebot/telebot" "$@"
