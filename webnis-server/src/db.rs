use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::{self, File};
use std::path::Path;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use actix::prelude::*;
use gdbm;
use rand::{thread_rng, Rng};
use rand::distributions::Uniform;
use serde::{self, Deserialize, Deserializer};
use serde_json::{self, json};

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
    static MAPS: RefCell<HashMap<String, GdbmDb>> = RefCell::new(HashMap::new());
}

// Actix background timer actor. We start one in
// every server, i.e. every thread, so we can do
// regular housekeeping.
#[derive(Default)]
pub(crate) struct Timer {
}

// Boilerplate to start and run the timer.
impl Actor for Timer {
    type Context  = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        // random timer interval between 1.75 and 2.25 seconds.
        let d = Duration::from_millis(1750 + thread_rng().sample(Uniform::new(0u64, 500)));
        ctx.run_interval(d, |t: &mut Timer, _ctx: &mut Context<Self>| {
            t.interval();
        });
    }

    fn stopping(&mut self, _ctx: &mut Self::Context) -> Running {
        Running::Stop
    }
}

impl Timer {
    // called from main() to start the timer.
    pub fn start_timer() {
        Timer::start_default();
    }

    // called every few seconds. See if any cached GdbmDb handle has been
    // unused for more than 5 seconds, if so, drop it.
    pub fn interval(&mut self) {
        MAPS.with(|maps| {
            let m = &mut *maps.borrow_mut();
            let now = SystemTime::now();

            let mut old = Vec::new();
            for (path, db) in m.iter_mut() {
                if let Ok(d) = now.duration_since(db.lastused) {
                    if d.as_secs() > 5 {
                        old.push(path.to_string());
                    }
                }
            }
            for o in &old {
                m.remove(o);
            }
        });
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
    MAPS.with(|maps| {
        // do we have an open handle.
        let m = &mut *maps.borrow_mut();
        let path = db_path.as_ref();
        let now = SystemTime::now();
        if let Some(db) = m.get_mut(path) {
            // yes. if it's valid, use it.
            if gdbm_check(path, db, now) {
                db.lastused = now;
                return db.handle.fetch(key).map_err(|_| WnError::KeyNotFound);
            }
            // invalid. drop handle.
            m.remove(path);
        }

        // try to open, then lookup, and save handle.
        let metadata = fs::metadata(path).map_err(|_| WnError::MapNotFound)?;
        let handle =
            gdbm::Gdbm::new(Path::new(path), 0, gdbm::READER, 0).map_err(|_| WnError::MapNotFound)?;
        let db = GdbmDb {
            file_name: path.to_string(),
            handle:    handle,
            modified:  metadata.modified().ok(),
            lastcheck: now,
            lastused:  now,
        };
        let res = db.handle.fetch(key).map_err(|_| WnError::KeyNotFound);
        m.insert(path.to_owned(), db);
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
