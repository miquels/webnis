
use std::sync::Mutex;
use std::cell::RefCell;
use std::collections::HashMap;
use std::iter::FromIterator;

use failure::ResultExt;
use serde_json;
use serde_json::Value as JValue;

//use rlua::{Function, Lua, MetaMethod, Result, UserData, UserDataMethods, Variadic};
use rlua::{self, Function, Lua, ToLua, MetaMethod, UserData, UserDataMethods};

use crate::{Webnis, util};
use crate::errors::*;

// main info that interpreter instances use to initialize.
struct LuaMaster {
    webnis: Webnis,
    name:   String,
    script: String,
}

// per-instance interpreter state.
struct LuaState {
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

    set_webnis_table(&lua, lua_master.webnis.clone());

    Some(LuaState{
        lua:    lua,
    })
}

/// Read the lua script from a file, and evaluate it. If it does evaluate
/// without errors, store the filename and the script so that we can later
/// create per-thread instances.
pub(crate) fn lua_init(name: &str, webnis: Webnis) -> Result<(), Error> {
    let mut guard = LUA_MASTER.lock().unwrap();
    let script = std::fs::read_to_string(name).context(format!("opening {}", name))?;
    let lua = Lua::new();
    if let Err(e) = lua.exec::<()>(&script, Some(name)) {
        merror!("parsing lua script:\n{}", e);
        Err(WnError::LuaError)?;
    }
    let lua_master = &mut *guard;
    *lua_master = Some(LuaMaster{
        name:   name.to_string(),
        script: script,
        webnis: webnis,
    });
    Ok(())
}

/// Recursively transform a serde_json::Value to a rlua::Value.
/// This is surprisingly easy!
fn json_value_to_lua<'a>(lua: &'a Lua, jv: serde_json::Value) -> rlua::Value<'a> {
    match jv {
        serde_json::Value::Null => rlua::Nil,
        serde_json::Value::Bool(b) => b.to_lua(lua).unwrap(),
        serde_json::Value::Number(n) => {
            if let Some(n) = n.as_i64() {
                n.to_lua(lua).unwrap()
            } else if let Some(n) = n.as_f64() {
                n.to_lua(lua).unwrap()
            } else {
                rlua::Nil
            }
        },
        serde_json::Value::String(s) => s.to_lua(lua).unwrap(),
        serde_json::Value::Array(a) => {
            a.into_iter()
                .map(|e| json_value_to_lua(lua, e))
                .collect::<Vec<_>>()
                .to_lua(lua)
                .unwrap_or(rlua::Nil)
        },
        serde_json::Value::Object(o) => {
            let hm : HashMap<String, rlua::Value> = HashMap::from_iter(
                o.into_iter()
                .map(|(k, v)| (k, json_value_to_lua(lua, v)))
            );
            hm.to_lua(lua).unwrap_or(rlua::Nil)
        },
    }
}

/// Recursively transform a rlua::Value to a serde_json::Value
fn lua_value_to_json(lua_value: rlua::Value) -> serde_json::Value {
    match lua_value {
        rlua::Value::Nil => JValue::Null,
        rlua::Value::Boolean(v) => JValue::Bool(v),
        rlua::Value::Integer(v) => From::from(v as i64),
        rlua::Value::Number(v) => From::from(v as f64),
        rlua::Value::String(v) => From::from(v.to_str().unwrap_or("").to_string()),
        rlua::Value::Table(t) => {
            let is_array = match t.raw_get::<usize, rlua::Value>(1) {
                Ok(rlua::Value::Nil) => false,
                Err(_) => false,
                _ => true,
            };
            if is_array {
                // this table has a sequence part. handle it as an array.
                let v = t.sequence_values::<rlua::Value>()
                    .filter_map(|res| res.ok())
                    .map(|e| lua_value_to_json(e))
                    .collect::<Vec<_>>();
                JValue::Array(v)
            } else {
                // It is an object.
                let hm = serde_json::map::Map::from_iter(
                    t.pairs::<String, rlua::Value>()
                        .filter_map(|res| res.ok())
                        .map(|(k, v)| (k, lua_value_to_json(v)))
                );
                JValue::Object(hm)
            }
        },
        _ => JValue::Null,
    }
}

/// lua_map calls a lua function. The return value is usually a map, or nil.
pub(crate) fn lua_map(mapname: &str, domain: &str, keyname: &str, keyval: &str) -> Result<serde_json::Value, WnError> {

    LUA.with(|lua_tls| {
        let lua_state1 = &*lua_tls.borrow();
        let lua_state = lua_state1.as_ref().unwrap();

        let globals = lua_state.lua.globals();
        let w_obj : rlua::Table = match globals.get("webnis") {
            Err(e) => {
                merror!("lua_map: error setting global webnis table:\n{}", e);
                return Err(WnError::LuaError);
            },
            Ok(o) => o,
        };
        w_obj.set("domain", domain).unwrap();

        let func : Function = match globals.get(mapname) {
            Ok(f) => f,
            Err(_e) => return Err(WnError::LuaFunctionNotFound),
        };

        let val = match func.call::<_, rlua::Value>((keyname, keyval)) {
            Ok(v) => v,
            Err(e) => {
                merror!("lua_map: executing {}:\n{}", mapname, e);
                return Err(WnError::LuaError);
            },
        };

        let jv = lua_value_to_json(val);
        Ok(jv)
    })
}

/// This is a userdata struct, passed to the lua authenticate hook.
/// It allows access to the username / email fields, but not to the
/// password field- but it can authenticate.
pub struct AuthInfo {
    pub username:       String,
    pub password:       String,
    pub map:            Option<String>,
    pub key:            Option<String>,
    pub extra:          HashMap<String, serde_json::Value>,
}

impl UserData for AuthInfo {
    fn add_methods(methods: &mut UserDataMethods<Self>) {
        methods.add_meta_method(MetaMethod::Index, |lua, this: &AuthInfo, arg: String| {
            match arg.as_str() {
                "username"  => this.username.clone().to_lua(lua).map(|x| Some(x)),
                "password"  => this.password.clone().to_lua(lua).map(|x| Some(x)),
                "map"       => this.map.clone().to_lua(lua).map(|x| Some(x)),
                "key"       => this.key.clone().to_lua(lua).map(|x| Some(x)),
                x => {
                    if let Some(jv) = this.extra.get(x) {
                        Ok(Some(json_value_to_lua(lua, jv.to_owned())))
                    } else {
                        Ok(None)
                    }
                },
            }
        });
        methods.add_method("checkpass", |_, this: &AuthInfo, arg: String| {
            Ok(util::check_unix_password(&this.password, &arg))
        });
    }
}

/// lua_auth calls a lua function.
/// returns a json value on success, json null on auth fail, error on any errors.
pub(crate) fn lua_auth(funcname: &str, domain: &str, ai: AuthInfo) -> Result<serde_json::Value, WnError> {

    LUA.with(|lua_tls| {
        let lua_state1 = &*lua_tls.borrow();
        let lua_state = lua_state1.as_ref().unwrap();

        let globals = lua_state.lua.globals();
        let w_obj : rlua::Table = match globals.get("webnis") {
            Err(e) => {
                merror!("lua_map: error setting global webnis table:\n{}", e);
                return Err(WnError::LuaError);
            },
            Ok(o) => o,
        };
        w_obj.set("domain", domain).unwrap();

        let func : Function = match globals.get(funcname) {
            Ok(f) => f,
            Err(_e) => return Err(WnError::LuaFunctionNotFound),
        };

        let val = match func.call::<_, rlua::Value>(ai) {
            Ok(v) => v,
            Err(e) => {
                merror!("lua_auth: executing {}:\n{}", funcname, e);
                return Err(WnError::LuaError);
            },
        };

        let jv = lua_value_to_json(val);
        Ok(jv)
    })
}

fn set_webnis_table(lua: &Lua, webnis: Webnis) {

    let table = lua.create_table().expect("failed to create table");
    let globals = lua.globals();

    let map_lookup = {
        let webnis = webnis.clone();
        lua.create_function(move |lua, (mapname, keyname, keyvalue) : (String, String, String)| {
            // it gets a bit verbose when you want to log errors
            // (as opposed to sending them up, which might be better..)
            let w_obj : rlua::Table = match lua.globals().get("webnis") {
                Ok(w) => w,
                Err(e) => {
                    warn!("map_lookup: get webnis global: {}", e);
                    return Err(e);
                },
            };
            let domain : String = match w_obj.get("domain") {
                Ok(d) => d,
                Err(e) => {
                    warn!("map_lookup: webnis.domain: {}", e);
                    return Err(e);
                },
            };
            let v = match webnis.lua_map_lookup(&domain, &mapname, &keyname, &keyvalue) {
                Ok(jv) => json_value_to_lua(lua, jv),
                Err(e) => {
                    warn!("map_lookup {} {}={}: {}", mapname, keyname, keyvalue, e);
                    rlua::Nil
                },
            };
            Ok(v)
        }).expect("failed to create func map_lookup()")
    };
    table.set("map_lookup", map_lookup).expect("failed to insert into table");
    //globals.set("webnis_map_lookup", map_lookup).unwrap();

    let map_auth = {
        let webnis = webnis.clone();
        lua.create_function(move |lua, (mapname, keyname, username, password) : (String, String, String, String)| {
            // it gets a bit verbose when you want to log errors
            // (as opposed to sending them up, which might be better..)
            let w_obj : rlua::Table = match lua.globals().get("webnis") {
                Ok(w) => w,
                Err(e) => {
                    warn!("map_lookup: get webnis global: {}", e);
                    return Err(e);
                },
            };
            let domain : String = match w_obj.get("domain") {
                Ok(d) => d,
                Err(e) => {
                    warn!("map_lookup: webnis.domain: {}", e);
                    return Err(e);
                },
            };
            let v = match webnis.lua_map_auth(&domain, &mapname, &keyname, &username, &password) {
                Ok(jv) => json_value_to_lua(lua, JValue::Bool(jv)),
                Err(e) => {
                    warn!("map_auth {} {}={}: {}", mapname, keyname, username, e);
                    rlua::Nil
                },
            };
            Ok(v)
        }).expect("failed to create func map_lookup()")
    };
    table.set("map_auth", map_auth).expect("failed to insert into table");
    //globals.set("webnis_map_auth", map_auth).unwrap();

    globals.set("webnis", table).expect("failed to set global webnis");

    // add a debugging function.
    let dprint = lua.create_function( |_, data: String| {
        debug!("{}", data);
        Ok(())
    }).unwrap();
    globals.set("dprint", dprint).unwrap();
}

