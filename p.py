#!/usr/bin/env python3
import sys
from ctypes import CDLL
lib = CDLL("target/debug/libjsonfuzz.so")
conf = lib.load_config(b'config.toml')
if not conf:
    print("Could not load config", file=sys.stderr)
    exit(1)
conf_buf = b'\x01\x01\xff\x00\x00\x00\x33'
lib.parse_buf(conf, conf_buf)
lib.free_config(conf)
