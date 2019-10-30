#!/usr/bin/env bash

find . -type f \
    -name '*.py' -o \
    -name '*.rs' -o \
    -name 'Cargo*' \
    | entr -c sh -c 'cargo build && ./p.py'
