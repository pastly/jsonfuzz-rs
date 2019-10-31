use serde_json;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs;
use std::os::raw::c_char;
use std::ptr;
use std::slice;
use std::str::FromStr;
use toml::value::{Table, Value};

type Map = serde_json::map::Map<String, serde_json::value::Value>;

#[derive(Debug)]
pub enum ValType {
    U8,
    U32,
    I8,
    I32,
    Str0,
}

impl FromStr for ValType {
    type Err = ();
    fn from_str(s: &str) -> Result<ValType, ()> {
        match s {
            "u8" => Ok(ValType::U8),
            "u32" => Ok(ValType::U32),
            "i8" => Ok(ValType::I8),
            "i32" => Ok(ValType::I32),
            "str" => Ok(ValType::Str0),
            _ => Err(()),
        }
    }
}

#[derive(Debug)]
pub struct Config {
    inner: Table,
}

impl Config {
    /// List all keys that we know about; i.e. all keys that exist in the config.toml
    fn keys(&self) -> Vec<&String> {
        // This needs to have a deterministic order. Currently it seems to be already. I was going
        // to alphabetize them, but they already are??
        self.inner.keys().collect()
    }

    /// List all the keys that the buf indicates it contains.
    fn contained_keys(&self, buf: &[u8]) -> Vec<String> {
        // This needs to have a deterministic order like keys(). Since we pull from keys() and it
        // has a deterministic order, we do too.
        let mut found = vec![];
        let mut i = 0;
        for k in self.keys() {
            // only bit that determines whether the key is contained in the buf is the last bit of
            // the byte
            if (buf[i] & 0x01) != 0 {
                found.push(k.clone());
            }
            i += 1;
        }
        found
    }

    /// Calculate the length, in bytes, of the value matching type val_type. If it is of variable
    /// length (e.g. a null-terminated string), it must start at the beginning of the given buf so
    /// we can use it to determine its length.
    fn value_len(val_type: &ValType, buf: &[u8]) -> usize {
        match val_type {
            ValType::I8 | ValType::U8 => 1,
            ValType::I32 | ValType::U32 => 4,
            ValType::Str0 => {
                // a null-terminated string. its length includes the null
                let mut len = 1;
                let mut i = 0;
                while buf[i] > 0 {
                    i += 1;
                    len += 1;
                }
                len
            }
        }
    }

    /// Calculate the start and end byte index of the given key: [start, end). Start is
    /// the index of the first byte and end is the index just after the last byte. Returns Err if
    /// the given key does not exist in the buf
    fn value_indices(&self, buf: &[u8], key: &str) -> Result<(ValType, usize, usize), ()> {
        let keys = self.contained_keys(buf);
        if !keys.contains(&String::from(key)) {
            return Err(());
        }
        // start will be at least the first byte after all the flag bytes at the front
        let mut start = self.keys().len();
        // iterate through keys until we find the one that matches the given key
        for key_i in keys {
            let val_type = self.inner[&key_i]["type"]
                .as_str()
                .unwrap() // assumes validate_config was called which requires type key to exist
                .parse::<ValType>()
                .unwrap(); // assumes validate_config was called which requires valid ValType
            if key_i != key {
                // if not our key, calculate offset to add to start
                start += Config::value_len(&val_type, &buf[start..]);
                assert!(start < buf.len());
            } else {
                // we found our key. Now calculate end
                let end = start + Config::value_len(&val_type, &buf[start..]);
                assert!(start < buf.len());
                assert!(end <= buf.len());
                return Ok((val_type, start, end));
            }
        }
        Err(())
    }

    fn new(table: Table) -> Self {
        Self { inner: table }
    }
}

fn validate_config(c: &Config) -> Result<(), Vec<String>> {
    let mut errs = vec![];
    for key in c.keys() {
        // all keys must be a table
        if !c.inner[key].is_table() {
            errs.push(format!("{} is not a table", key));
            continue;
        }
        let table = c.inner[key].as_table().unwrap();
        // all tables must have a type param
        if table.keys().find(|k| *k == "type").is_none() {
            errs.push(format!("{}.type does not exist", key));
            continue;
        }
        // all type params must be a valid ValType
        let _val_type = match table["type"].as_str().unwrap().parse::<ValType>() {
            Ok(t) => t,
            Err(_) => {
                errs.push(format!(
                    "{}.type is {} which is invalid",
                    key, table["type"]
                ));
                continue;
            }
        };
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

fn _load_config(fname: &str) -> Result<Config, Box<dyn std::error::Error + 'static>> {
    eprintln!("Loading config from {}", fname);
    let data = fs::read_to_string(fname)?.parse::<Value>()?;
    Ok(Config::new(data.as_table().unwrap().clone()))
}

#[no_mangle]
pub extern "C" fn load_config(fname_in: *const c_char) -> *const Config {
    let fname = unsafe {
        match CStr::from_ptr(fname_in).to_str() {
            Ok(f) => f,
            Err(_) => {
                let broken_fname = CStr::from_ptr(fname_in).to_string_lossy();
                eprintln!("'{}' could not be parsed into a &str", broken_fname);
                return ptr::null();
            }
        }
    };
    let conf = match _load_config(fname) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", e);
            return ptr::null();
        }
    };
    match validate_config(&conf) {
        Err(errs) => {
            for e in errs {
                eprintln!("{}", e);
            }
            return ptr::null();
        }
        _ => {}
    };
    let conf_box = Box::new(conf);
    Box::into_raw(conf_box)
}

fn _to_json(conf: &Config, buf: &[u8]) -> Map {
    let keys = conf.contained_keys(buf);
    let mut dict: HashMap<String, Value> = HashMap::new();
    for key in keys {
        match conf.value_indices(buf, &key) {
            Ok((val_type, start, end)) => {
                match val_type {
                    ValType::U8 => {
                        let v = buf[start] as u8;
                        dict.insert(key.clone(), Value::Integer(v as i64));
                    }
                    ValType::U32 => {
                        let v = ((buf[start + 0] as u32) << 24)
                            | ((buf[start + 1] as u32) << 16)
                            | ((buf[start + 2] as u32) << 8)
                            | ((buf[start + 3] as u32) << 0);
                        dict.insert(key.clone(), Value::Integer(v as i64));
                    }
                    ValType::I8 => {
                        let v = buf[start] as i8;
                        dict.insert(key.clone(), Value::Integer(v as i64));
                    }
                    ValType::I32 => {
                        let v = ((buf[start + 0] as i32) << 24)
                            | ((buf[start + 1] as i32) << 16)
                            | ((buf[start + 2] as i32) << 8)
                            | ((buf[start + 3] as i32) << 0);
                        dict.insert(key.clone(), Value::Integer(v as i64));
                    }
                    ValType::Str0 => {
                        assert_eq!(buf[end - 1], 0x00);
                        let s = String::from_utf8_lossy(&buf[start..end - 1]).to_string();
                        dict.insert(key.clone(), Value::String(s));
                    }
                }
                eprintln!(
                    "{} ({}) is a {:?} at [{}, {})",
                    key, dict[&key], val_type, start, end
                );
            }
            Err(_) => {
                eprintln!("Err with key {}", key);
            }
        };
    }
    serde_json::json!(dict).as_object().unwrap().clone()
    //serde_json::to_string_pretty(&dict).unwrap()
    //serde_json::to_string(&dict).unwrap()
}

#[no_mangle]
pub extern "C" fn to_json(
    conf_ptr: *const Config,
    buf: *const u8,
    buf_len: usize,
) -> *const c_char {
    let conf = unsafe { &*conf_ptr };
    let buf = unsafe { slice::from_raw_parts(buf, buf_len) };
    let j = _to_json(conf, buf);
    let s = serde_json::to_string_pretty(&j).unwrap();
    let c_str = CString::new(s).unwrap();
    c_str.into_raw()
}

fn _from_json(conf: &Config, json: Map) -> Vec<u8> {
    let mut header_buf = vec![];
    let mut body_buf = vec![];
    // quick sanity check: make sure all keys in the json are known in the config
    for json_key in json.keys() {
        assert!(conf.keys().contains(&json_key));
    }
    for conf_key in conf.keys() {
        if json.contains_key(conf_key) {
            header_buf.push(0x01);
            match conf.inner[conf_key]["type"]
                .as_str()
                .unwrap()
                .parse::<ValType>()
                .unwrap()
            {
                ValType::I8 | ValType::U8 => {
                    let i = json[conf_key].as_i64().unwrap();
                    body_buf.push(i as u8);
                }
                ValType::I32 | ValType::U32 => {
                    let i = json[conf_key].as_i64().unwrap();
                    body_buf.push((i >> 24) as u8);
                    body_buf.push((i >> 16) as u8);
                    body_buf.push((i >> 8) as u8);
                    body_buf.push(i as u8);
                }
                ValType::Str0 => {
                    let s = json[conf_key].as_str().unwrap();
                    body_buf.extend_from_slice(s.as_bytes());
                    body_buf.push(0x00);
                }
            };
        } else {
            header_buf.push(0x00);
        }
    }
    eprintln!("{:?}", header_buf);
    eprintln!("{:?}", body_buf);
    let mut buf = header_buf;
    buf.append(&mut body_buf);
    buf.shrink_to_fit();
    assert_eq!(buf.len(), buf.capacity());
    buf
}

#[no_mangle]
pub extern "C" fn from_json(
    conf_ptr: *const Config,
    json_c_str: *mut c_char,
    buf_len_out: *mut usize,
) -> *const u8 {
    let conf = unsafe { &*conf_ptr };
    let json_str = unsafe { CStr::from_ptr(json_c_str) }.to_str().unwrap();
    let json = serde_json::from_str(json_str).unwrap();
    let out = _from_json(conf, json);
    assert_eq!(out.len(), out.capacity());
    unsafe {
        *buf_len_out = out.len();
    }
    eprintln!("{:?}", out);
    let ret = out.as_ptr();
    std::mem::forget(out);
    ret
}

#[no_mangle]
pub extern "C" fn free_config(conf_ptr: *mut Config) {
    unsafe {
        drop(Box::from_raw(conf_ptr));
    }
}

#[no_mangle]
pub extern "C" fn free_string(s: *mut c_char) {
    unsafe {
        drop(CString::from_raw(s));
    }
}

#[no_mangle]
pub extern "C" fn free_byte_vec(v: *mut u8, len: usize) {
    unsafe {
        drop(Vec::from_raw_parts(v, len, len));
    }
}

#[cfg(test)]
mod identity_tests {
    use super::Config;

    fn c(s: &str) -> Config {
        use super::validate_config;
        use toml::value::Value;
        let c = Config::new(s.parse::<Value>().unwrap().as_table().unwrap().clone());
        assert!(validate_config(&c).is_ok());
        c
    }

    fn json_identity(conf: &Config, s: &str) {
        use super::Map;
        use super::{_from_json, _to_json};
        let json_in: Map = serde_json::from_str(s).unwrap();
        let json_out = _to_json(&conf, &_from_json(&conf, json_in.clone()));
        assert_eq!(json_in, json_out);
    }

    fn bytes_identity(conf: &Config, bytes_in: Vec<u8>) {
        use super::{_from_json, _to_json};
        let bytes_out = _from_json(&conf, _to_json(&conf, &bytes_in));
        assert_eq!(bytes_in, bytes_out);
    }

    #[test]
    fn u8() {
        let conf = c("[a]\ntype = 'u8'");
        for i in 0..=255u8 {
            let json_str = format!(r#"{{"a": {}}}"#, i);
            json_identity(&conf, &json_str);
            bytes_identity(&conf, vec![1u8, i]);
        }
    }

    #[test]
    fn i8() {
        let conf = c("[a]\ntype = 'i8'");
        for i in 0..=255u8 {
            let json_str = format!(r#"{{"a": {}}}"#, i as i8);
            json_identity(&conf, &json_str);
            bytes_identity(&conf, vec![1u8, i]);
        }
    }

    #[test]
    fn u32() {
        let conf = c("[a]\ntype = 'u32'");
        for i in vec![0u32, 1, 100, 1_000_000, 999_999_999, u32::max_value()] {
            let json_str = format!(r#"{{"a": {}}}"#, i);
            json_identity(&conf, &json_str);
            bytes_identity(
                &conf,
                vec![
                    1u8,
                    (i >> 24) as u8,
                    (i >> 16) as u8,
                    (i >> 8) as u8,
                    i as u8,
                ],
            );
        }
    }

    #[test]
    fn i32() {
        let conf = c("[a]\ntype = 'i32'");
        for i in vec![
            0i32,
            -1,
            1,
            1_000_000,
            -1_000_000,
            999_999_999,
            -999_999_999,
            i32::min_value(),
            i32::max_value(),
        ] {
            let json_str = format!(r#"{{"a": {}}}"#, i);
            json_identity(&conf, &json_str);
            bytes_identity(
                &conf,
                vec![
                    1u8,
                    (i >> 24) as u8,
                    (i >> 16) as u8,
                    (i >> 8) as u8,
                    i as u8,
                ],
            );
        }
    }

    #[test]
    fn str0() {
        let conf = c("[a]\ntype = 'str'");
        for s in vec!["", "h", "hello", "a b", " a "] {
            let json_str = format!(r#"{{"a": "{}"}}"#, s);
            json_identity(&conf, &json_str);
            let mut bytes = vec![0x01];
            bytes.extend(s.bytes());
            bytes.push(0x00);
            bytes_identity(&conf, bytes);
        }
    }

    #[test]
    fn empty() {
        for c_str in vec![
            "",
            "[a]\ntype = 'u32'",
            "[a]\ntype = 'u32'\n[b]\ntype = 'i8'",
            "[a]\ntype = 'u32'\n[b]\ntype = 'i8'\n[c]\ntype = 'str'",
        ] {
            let conf = c(c_str);
            json_identity(&conf, "{}");
            bytes_identity(&conf, vec![0x00; conf.keys().len()]);
        }
    }
}
