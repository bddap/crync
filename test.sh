#!/bin/bash

set -euxo pipefail

cargo check
cargo test

keypair=$(cargo run -- gen)
key_secret=$(echo $keypair | jq -r .secret)
key_public=$(echo $keypair | jq -r .public)

cargo run listen -- $key_secret &
echo hello worl | cargo run gensend -- $key_public

wait
echo done
