#!/usr/bin/env python3
import sys
from ctypes import CDLL, create_string_buffer, c_char_p, byref, c_size_t,\
    c_ubyte, POINTER, c_void_p, addressof
lib = CDLL("target/debug/libjsonfuzz.so")

conf_t = c_void_p
lib.load_config.argtypes = [c_char_p]
lib.load_config.restype = conf_t
lib.to_json.argtypes = [conf_t, POINTER(c_ubyte), c_size_t]
lib.to_json.restype = c_void_p
lib.free_string.argtypes = [c_char_p]
lib.free_string.restype = None
lib.from_json.argtypes = [conf_t, c_char_p, POINTER(c_size_t)]
lib.from_json.restype = POINTER(c_ubyte)
lib.free_byte_vec.argtypes = [POINTER(c_ubyte)]
lib.free_byte_vec.restype = None


conf = lib.load_config(b'config.toml')
if not conf:
    print("Could not load config", file=sys.stderr)
    exit(1)

######
# From bytes to json
######
# create_string_buffer adds a \x00 to the end. take all but that null
conf_bytes = b'\x01\x01\x01\x01MATT\x00\xff\x00\x00\x00\x33hello\x00'
conf_bytes_ptr = (c_ubyte * len(conf_bytes)).from_buffer_copy(conf_bytes)

s = c_char_p(lib.to_json(conf, conf_bytes_ptr, len(conf_bytes)))
print(s.value.decode('utf-8'))
lib.free_string(s)

######
# From json to bytes
######
out_len = c_size_t(0)
j = create_string_buffer(b'{"aa": "MATT","age": 255,"bbb": 51,"zz": "hello"}')
out = lib.from_json(conf, j, byref(out_len))
out_type = c_ubyte * out_len.value
out_buf = out_type.from_address(addressof(out.contents))
print(bytes(out_buf))
lib.free_byte_vec(out, out_len)


lib.free_config(conf)
