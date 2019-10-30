use std::fs;
use std::ptr;
use std::slice;
use std::str::FromStr;
use toml::value::{Table, Value};
use std::collections::HashMap;

#[derive(Debug)]
pub enum ValType {
    U8,
    U32,
    I8,
    I32,
}

impl FromStr for ValType {
    type Err = ();
    fn from_str(s: &str) -> Result<ValType, ()> {
        match s {
            "u8" => Ok(ValType::U8),
            "u32" => Ok(ValType::U32),
            "i8" => Ok(ValType::I8),
            "i32" => Ok(ValType::I32),
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
            if buf[i] != 0 {
                found.push(k.clone());
            }
            i += 1;
        }
        found
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
        let mut start = keys.len();
        // iterate through keys until we find the one that matches the given key
        for key_i in keys {
            let val_type = self.inner[&key_i]["type"]
                .as_str()
                .unwrap() // assumes validate_config was called which requires type key to exist
                .parse::<ValType>()
                .unwrap(); // assumes validate_config was called which requires valid ValType
            if key_i != key {
                // if not our key, calculate offset to add to start
                start += match val_type {
                    ValType::I8 | ValType::U8 => 1,
                    ValType::I32 | ValType::U32 => 4,
                };
            } else {
                // we found our key. Now calculate end
                let end = start
                    + match val_type {
                        ValType::I8 | ValType::U8=> 1,
                        ValType::I32 | ValType::U32 => 4,
                    };
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
    println!("Loading config from {}", fname);
    let data = fs::read_to_string(fname)?.parse::<Value>()?;
    Ok(Config::new(data.as_table().unwrap().clone()))
}

use std::ffi::CStr;
use std::os::raw::c_char;

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

#[no_mangle]
pub extern "C" fn parse_buf(conf_ptr: *const Config, buf: *const u8, buf_len: usize) {
    // TODO: buf needs a length param otherwise we don't know how big it is and will happily read
    // garbage memory
    println!("{}", buf_len);
    let conf = unsafe { &*conf_ptr };
    let buf = unsafe { slice::from_raw_parts(buf, buf_len) };
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
                        let v =
                            ((buf[start+0] as u32) << 24) |
                            ((buf[start+1] as u32) << 16) |
                            ((buf[start+2] as u32) <<  8) |
                            ((buf[start+3] as u32) <<  0);
                        dict.insert(key.clone(), Value::Integer(v as i64));
                    }
                    ValType::I8 => {
                        let v = buf[start] as i8;
                        dict.insert(key.clone(), Value::Integer(v as i64));
                    }
                    ValType::I32 => {
                        let v =
                            ((buf[start+0] as i32) << 24) |
                            ((buf[start+1] as i32) << 16) |
                            ((buf[start+2] as i32) <<  8) |
                            ((buf[start+3] as i32) <<  0);
                        dict.insert(key.clone(), Value::Integer(v as i64));
                    }
                }
                eprintln!("{} ({}) is a {:?} at [{}, {})", key, dict[&key], val_type, start, end);
            },
            Err(_) => {
                eprintln!("Err with key {}", key);
            },
        };
    }
    println!("{}", serde_json::to_string_pretty(&dict).unwrap());
}

#[no_mangle]
pub extern "C" fn free_config(conf_ptr: *mut Config) {
    unsafe {
        drop(Box::from_raw(conf_ptr));
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
