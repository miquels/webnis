use std::path::Path;
use std::collections::HashMap;
use std::cell::RefCell;
use std::fs::{self,File};
use std::time::SystemTime;

use serde_json;
use gdbm;

struct GdbmDb {
    #[allow(unused)]
    file_name:  String,
    modified:   Option<SystemTime>,
    lastcheck:  SystemTime,
    handle:     gdbm::Gdbm,
}

// Unfortunately `gdbm' is not thread-safe.
thread_local! {
    static MAPS: RefCell<HashMap<String, GdbmDb>> = RefCell::new(HashMap::new());
}

pub enum DbError {
    /// key not found in map.
    NotFound,
    /// map not found. caller might handle this as a "fail" instead of "key not found".
    MapNotFound,
    /// ditto but for any other error.
    Other,
}

pub fn gdbm_lookup(db_path: impl AsRef<str>, key: &str) -> Result<String, DbError> {

    MAPS.with(|maps| {

        // do we have an open handle.
        let m = &mut *maps.borrow_mut();
        let path = db_path.as_ref();
        let mut remove = false;
        if let Some(db) = m.get(path) {

            // yes. now, every 5 secs, see if database file has changed.
            let mut reopen = false;
            if let Ok(d) = db.lastcheck.duration_since(SystemTime::now()) {
                if d.as_secs() > 5 {
                    if let Ok(metadata) = fs::metadata(path) {
                        reopen = match (metadata.modified(), db.modified) {
                            (Ok(m1), Some(m2)) => m1 != m2,
                            _ => true,
                        };
                    }
                }
            }

            // no change, look up and return.
            if !reopen {
                return db.handle.fetch(key).map_err(|_| DbError::NotFound);
            }

            remove = true;
        }
        if remove {
            m.remove(path);
        }

        // try to open, then lookup, and save handle.
        let metadata = fs::metadata(path).map_err(|_| DbError::MapNotFound)?;
        let handle = gdbm::Gdbm::new(Path::new(path), 0, gdbm::READER, 0)
            .map_err(|_| DbError::MapNotFound)?;
        let db = GdbmDb{
            file_name:  path.to_string(),
            handle:     handle,
            modified:   metadata.modified().ok(),
            lastcheck:  SystemTime::now(),
        };
        let res = db.handle.fetch(key).map_err(|_| DbError::NotFound);
        m.insert(path.to_owned(), db);
        res
    })
}

pub fn json_lookup(db_path: impl AsRef<str>, keyname: &str, keyval: &str) -> Result<serde_json::Value, DbError> {
    let file = File::open(db_path.as_ref()).map_err(|_| DbError::MapNotFound)?;
    let entries : serde_json::Value = serde_json::from_reader(file).map_err(|_| DbError::Other)?;
    let mut idx : usize = 0;
    let keyval = match keyval.parse::<u64>() {
        Ok(num) => json!(num),
        Err(_) => json!(keyval),
    };
    loop {
        let obj = match entries.get(idx) {
            None => break,
            Some(obj) => obj,
        };
        if obj.get(keyname) == Some(&keyval) {
            return Ok(obj.to_owned());
        }
        idx += 1;
    }
    Err(DbError::NotFound)
}

