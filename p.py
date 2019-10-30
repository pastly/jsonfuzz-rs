#!/usr/bin/env python3
import sys
from ctypes import CDLL, create_string_buffer
lib = CDLL("target/debug/libjsonfuzz.so")
conf = lib.load_config(b'config.toml')
if not conf:
    print("Could not load config", file=sys.stderr)
    exit(1)

# create_string_buffer adds a \x00 to the end. take all but that null
conf_buf = create_string_buffer(b'\x01\x01\xff\x00\x00\x00\x33')[:-1]
lib.parse_buf(conf, conf_buf, len(conf_buf))
lib.free_config(conf)
