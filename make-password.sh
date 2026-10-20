#!/usr/bin/env sh
# Prints the SITE_PASSWORD_HASH line for .env. Caddy prompts for the password itself,
# so it never appears in shell history or the process list.
set -eu
HASH=$(docker run --rm -it caddy:2 caddy hash-password | tr -d '\r')
# Single quotes: Compose reads single-quoted .env values literally, so the $ signs in the hash survive.
printf "SITE_PASSWORD_HASH='%s'\n" "$HASH"
