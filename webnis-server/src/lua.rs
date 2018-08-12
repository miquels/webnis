
use std;
use std::io;
use std::sync::Mutex;
use std::cell::RefCell;
use std::collections::HashMap;

use super::webnis::Webnis;
use super::db::DbError;

use serde_json;
use serde_json::Value as JValue;

//use rlua::{Function, Lua, MetaMethod, Result, UserData, UserDataMethods, Variadic};
use rlua::{self, Function, Lua};

// main info that interpreter instances use to initialize.
struct LuaMaster {
    webnis: Webnis,
    name:   String,
    script: String,
}

// per-instance interpreter state.
struct LuaState {
    webnis: Webnis,
    lua:    Lua,
}

// for now, 1 interpreter per thread. this might be excessive- perhaps
// we want to just start a maximum of N interpreters and multiplex
// over them. Hey, using actix actors perhaps.
thread_local! {
    static LUA: RefCell<Option<LuaState>> = RefCell::new(local_lua_init());
}

lazy_static! {
    static ref LUA_MASTER: Mutex<Option<LuaMaster>> = Mutex::new(None);
}

/// This is called the first time the thread-local LUA is referenced.
/// Try to start up an interpreter.
fn local_lua_init() -> Option<LuaState> {
    let guard = LUA_MASTER.lock().unwrap();
    let lua_master = match &*guard {
        Some(l) => l,
        None => {
            debug!("LUA not initialized but someone is trying to use it");
            return None;
        },
    };
    let lua = Lua::new();
    if let Err(e) = lua.exec::<()>(&lua_master.script, Some(lua_master.name.as_str())) {
        panic!("error loading lua script {}: {}", lua_master.name, e);
    }

    // add functionality.
    {
        let webnis = lua_master.webnis.clone();

        let map_lookup = lua.create_function(move |lua, (domain, mapname, keyname, keyvalue) : (String, String, String, String)| {
            let mut v = rlua::Variadic::<rlua::Table>::new();
            match webnis.map_lookup(&domain, &mapname, &keyname, &keyvalue) {
                Ok(jv) => v.push(json_value_to_lua(lua, jv)),
                Err(_) => {},
            };
            Ok(v)
        }).unwrap();
        lua.globals().set("map_lookup", map_lookup).unwrap();
    }

    Some(LuaState{
        webnis: lua_master.webnis.clone(),
        lua:    lua,
    })
}

/// Read the lua script from a file, and evaluate it. If it does evaluate
/// without errors, store the filename and the script so that we can later
/// create per-thread instances.
pub(crate) fn lua_init(name: &str, webnis: Webnis) -> Result<(), io::Error> {
    let mut guard = LUA_MASTER.lock().unwrap();
    let script = std::fs::read_to_string(name)?;
    let lua = Lua::new();
    lua.exec::<()>(&script, Some(name))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))
        .map(|_| ())?;
    let lua_master = &mut *guard;
    *lua_master = Some(LuaMaster{
        name:   name.to_string(),
        script: script,
        webnis: webnis,
    });
    Ok(())
}

fn json_value_to_lua<'a>(lua: &'a Lua, jv: serde_json::Value) -> rlua::Table<'a> {
    let table = lua.create_table().unwrap();
    let hm : HashMap<String, serde_json::Value> = serde_json::from_value(jv).unwrap();
    for (k, v) in hm.into_iter() {
        match v {
            serde_json::Value::Bool(v) => {
                // println!("table.set({}, {}", k, v);
                table.set(k, v).unwrap();
            },
            serde_json::Value::Number(n) => {
                // println!("table.set({}, {}", k, n);
                if let Some(v) = n.as_i64() {
                    table.set(k, v).unwrap()
                }
            },
            serde_json::Value::String(v) => {
                // println!("table.set({}, {}", k, v);
                table.set(k, v).unwrap();
            },
            _ => {},
        }
    }
    table
}

enum NumOrText {
    Num(i64),
    Text(String),
}

type LuaMap<'a> = HashMap<String, rlua::Value<'a>>;
type JsonMap = HashMap<String, serde_json::Value>;

fn lua_map_to_json(lua_map: LuaMap) -> serde_json::Value {
    let mut hm = serde_json::Map::new();
    for (k, v) in lua_map.into_iter() {
        let newv = match v {
            rlua::Value::Boolean(v) => JValue::Bool(v),
            rlua::Value::Integer(v) => From::from(v as f64),
            rlua::Value::Number(v) => From::from(v as f64),
            rlua::Value::String(v) => From::from(v.to_str().unwrap_or("").to_string()),
            //Table(v) => ...TODO
            _ => JValue::String("imaginative".to_string()),
        };
        hm.insert(k, newv);
    }
    JValue::Object(hm)
}

/// lua_map calls a lua function. The return value is always a map.
pub(crate) fn lua_map(mapname: &str, domain: &str, keyname: &str, keyval: &str) -> Result<serde_json::Value, io::Error> {

    LUA.with(|lua_tls| {
        let lua_state1 = &*lua_tls.borrow();
        let lua_state = lua_state1.as_ref().unwrap();
        let func: Function = lua_state.lua.globals().get(mapname).unwrap();
        let hm = func.call::<_, LuaMap>((domain, keyname, keyval)).unwrap();
        // println!("heya hm now {:#?}", hm);
        let jv = lua_map_to_json(hm);
        // println!("heya jv now {:#?}", jv);
        Ok(jv)
    })
}

