use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::{self, File};
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex, Weak};
use std::time::SystemTime;

use serde::{Deserialize, Deserializer};
use serde_json::json;
use tokio::task;
use tokio::time::{self, Duration};

use crate::errors::*;

struct GdbmDb {
    #[allow(unused)]
    file_name: String,
    modified: Option<SystemTime>,
    lastcheck: SystemTime,
    lastused: SystemTime,
    handle: gdbm::Gdbm,
}

// Unfortunately `gdbm' is not thread-safe.
thread_local! {
    static LOCAL_MAPS: RefCell<HashMap<String, Arc<Mutex<Option<GdbmDb>>>>> = RefCell::new(HashMap::new());
}

// We keep a global vector of weak references to the thread-local maps for housekeeping.
lazy_static! {
    static ref GLOBAL_MAPS: Mutex<Vec<Weak<Mutex<Option<GdbmDb>>>>> = Mutex::new(Vec::new());
}

#[derive(Default)]
pub(crate) struct Timer;

impl Timer {
    // called from main() to start the timer.
    pub async fn start_timer() {
        task::spawn(async {
            loop {
                time::sleep(Duration::from_millis(942)).await;
                Timer::interval();
            }
        });
    }

    // called every second. See if any cached GdbmDb handle has been
    // unused for more than 5 seconds, if so, drop it.
    fn interval() {
        let now = SystemTime::now();
        let mut maps = GLOBAL_MAPS.lock().unwrap();

        let mut idx = 0;
        while idx < maps.len() {

            // See if the owning Arc still is around, then lock.
            let opt_arc = maps[idx].upgrade();
            let mut opt_db = match opt_arc.as_ref() {
                Some(arc) => {
                    // Upgrade to strong reference succeeded, now lock inner entry.
                    arc.lock().unwrap()
                },
                None => {
                    // This is a weak reference and the original Arc is gone.
                    maps.remove(idx);
                    continue;
                }
            };

            // See if there still is an inner GdbmDb.
            let db = match opt_db.as_mut() {
                Some(db) => db,
                None => {
                    // No inner GdbmDb anymore.
                    maps.remove(idx);
                    continue;
                },
            };

            // Older than 5 secs, remove.
            if let Ok(d) = now.duration_since(db.lastused) {
                if d.as_secs() > 5 {
                    opt_db.take();
                    maps.remove(idx);
                    continue;
                }
            }

            idx += 1;
        }
    }
}

fn gdbm_check(path: &str, db: &mut GdbmDb, now: SystemTime) -> bool {
    let mut valid = true;
    if let Ok(d) = now.duration_since(db.lastcheck) {
        if d.as_secs() > 5 {
            if let Ok(metadata) = fs::metadata(path) {
                valid = match (metadata.modified(), db.modified) {
                    (Ok(m1), Some(m2)) => m1 == m2,
                    _ => false,
                };
            }
            if valid {
                db.lastcheck = now;
            }
        }
    }
    valid
}

pub fn gdbm_lookup(db_path: impl AsRef<str>, key: &str) -> Result<String, WnError> {
    LOCAL_MAPS.with(|maps| {
        // do we have an open handle.
        let m = &mut *maps.borrow_mut();
        let path = db_path.as_ref();
        let now = SystemTime::now();
        if let Some(arc) = m.get_mut(path) {
            if let Some(db) = arc.lock().unwrap().as_mut() {
                // yes. if it's valid, use it.
                if gdbm_check(path, db, now) {
                    db.lastused = now;
                    return db.handle.fetch(key).map_err(|_| WnError::KeyNotFound);
                }
            }
            // invalid. drop handle.
            m.remove(path);
        }

        // try to open, then lookup, and save handle.
        let metadata = fs::metadata(path).map_err(|_| WnError::MapNotFound)?;
        let handle =
            gdbm::Gdbm::new(Path::new(path), 0, gdbm::Open::READER, 0).map_err(|_| WnError::MapNotFound)?;
        let db = GdbmDb {
            file_name: path.to_string(),
            handle:    handle,
            modified:  metadata.modified().ok(),
            lastcheck: now,
            lastused:  now,
        };
        let res = db.handle.fetch(key).map_err(|_| WnError::KeyNotFound);

        let arc = Arc::new(Mutex::new(Some(db)));
        let mut global = GLOBAL_MAPS.lock().unwrap();
        global.push(Arc::downgrade(&arc));
        m.insert(path.to_owned(), arc);

        res
    })
}

pub fn json_lookup(
    db_path: impl AsRef<str>,
    keyname: &str,
    keyval: &str,
) -> Result<serde_json::Value, WnError>
{
    let file = File::open(db_path.as_ref()).map_err(|_| WnError::MapNotFound)?;
    let entries: serde_json::Value = serde_json::from_reader(file).map_err(|_| WnError::DbOther)?;
    let mut idx: usize = 0;
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
    Err(WnError::KeyNotFound)
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub enum MapType {
    Gdbm,
    Json,
    Lua,
    None,
}

impl FromStr for MapType {
    type Err = WnError;

    fn from_str(s: &str) -> Result<MapType, WnError> {
        let f = match s {
            "gdbm" => MapType::Gdbm,
            "json" => MapType::Json,
            "lua" => MapType::Lua,
            _ => return Err(WnError::UnknownMapType),
        };
        Ok(f)
    }
}

// Serde helper
pub fn deserialize_map_type<'de, D>(deserializer: D) -> Result<MapType, D::Error>
where D: Deserializer<'de> {
    let s = String::deserialize(deserializer)?;
    MapType::from_str(&s).map_err(serde::de::Error::custom)
}

impl Default for MapType {
    fn default() -> MapType {
        MapType::None
    }
}
