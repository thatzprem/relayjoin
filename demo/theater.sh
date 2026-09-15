#!/usr/bin/env bash
# Start Payjoin Theater with two signet wallets.
#
# Each argument is a file of the two `export` lines printed by
# `cargo run -p pjn-receiver -- keygen`: one wallet for Alice, one for Bob.
#
#   demo/theater.sh alice.env bob.env [extra pjn-theater flags]
#
# Both wallets need signet coins. Bob especially: a payjoin receiver must add one
# of its own coins, so an empty Bob cannot take part at all.
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 ALICE_ENV_FILE BOB_ENV_FILE [pjn-theater flags]" >&2
  exit 2
fi

read_wallet() {
  (
    unset PJN_DESCRIPTOR PJN_CHANGE_DESCRIPTOR
    set -a
    # shellcheck disable=SC1090
    . "$1"
    set +a
    if [ -z "${PJN_DESCRIPTOR:-}" ] || [ -z "${PJN_CHANGE_DESCRIPTOR:-}" ]; then
      echo "$1 does not define PJN_DESCRIPTOR and PJN_CHANGE_DESCRIPTOR" >&2
      exit 1
    fi
    printf '%s\n%s\n' "$PJN_DESCRIPTOR" "$PJN_CHANGE_DESCRIPTOR"
  )
}

mapfile -t ALICE < <(read_wallet "$1")
mapfile -t BOB < <(read_wallet "$2")
shift 2

export PJN_ALICE_DESCRIPTOR="${ALICE[0]}" PJN_ALICE_CHANGE_DESCRIPTOR="${ALICE[1]}"
export PJN_BOB_DESCRIPTOR="${BOB[0]}" PJN_BOB_CHANGE_DESCRIPTOR="${BOB[1]}"

exec cargo run --release -p pjn-theater -- "$@"
