#!/usr/bin/env bash

find . -type f \
    -name '*.py' -o \
    -name '*.rs' -o \
    -name 'Cargo*' \
    | entr -c cargo test

# find . -type f \
#     -name '*.py' -o \
#     -name '*.rs' -o \
#     -name 'Cargo*' \
#     | RUST_BACKTRACE=1 entr -c sh -c 'cargo build && ./p.py'
