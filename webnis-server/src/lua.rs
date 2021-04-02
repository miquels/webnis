use std::cell::RefCell;
use std::collections::HashMap;
use std::iter::FromIterator;
use std::net::IpAddr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::SystemTime;

use failure::ResultExt;
use serde_json;
use serde_json::Value as JValue;

use rlua::{self, Function, Lua, MetaMethod, ToLua, UserData, UserDataMethods};

use crate::datalog::{self, Datalog};
use crate::errors::*;
use crate::{util, webnis::Webnis};

// main info that interpreter instances use to initialize.
struct LuaMaster {
    name:   String,
    script: String,
}

// per-instance interpreter state.
struct LuaState {
    lua:        Lua,
    did_init:   bool,
}

// for now, 1 interpreter per thread. this might be excessive- perhaps
// we want to just start a maximum of N interpreters and multiplex
// over them. Hey, using actix actors perhaps.
thread_local! {
    static LUA: RefCell<LuaState> = RefCell::new(local_lua_init());
}

// One syslog instance per thread.
type SysLogger = syslog::Logger<syslog::LoggerBackend, syslog::Formatter3164>;
thread_local! {
    static LOG: RefCell<Option<SysLogger>> = RefCell::new(None);
}

lazy_static! {
    static ref LUA_MASTER: Mutex<Option<LuaMaster>> = Mutex::new(None);
}

/// This is called the first time the thread-local LUA is referenced.
/// Try to start up an interpreter.
fn local_lua_init() -> LuaState {
    let guard = LUA_MASTER.lock().unwrap();
    let lua_master = match &*guard {
        Some(l) => l,
        None => panic!("LUA not initialized but someone is trying to use it"),
    };
    let lua = Lua::new();
    if let Err::<(), _>(e) = lua.context(|ctx| {
        // set globals
        set_globals(ctx);
        // load the script.
        let chunk = ctx.load(&lua_master.script);
        let chunk = chunk.set_name(&lua_master.name)?;
        chunk.exec()
    }) {
        panic!("error loading lua script {}: {}", lua_master.name, e);
    }

    LuaState { lua: lua, did_init: false }
}

fn do_syslog(msg: &str) {
    LOG.with(|log| {
        let mut log = log.borrow_mut();

        if let Some(l) = log.as_mut() {
            let _ = l.info(msg);
            return;
        }

        let formatter = syslog::Formatter3164 {
            facility: syslog::Facility::LOG_DAEMON,
            hostname: None,
            process: "webnis-server".into(),
            pid: 0,
        };
        match syslog::unix(formatter) {
            Ok(mut l) => {
                let _ = l.info(msg);
                *log = Some(l);
            },
            Err(e) => {
                eprintln!("webnis-server: could not connect to syslog: {}", e);
            },
        }
    })
}

/// Read the lua script from a file, and evaluate it. If it does evaluate
/// without errors, store the filename and the script so that we can later
/// create per-thread instances.
pub(crate) fn lua_init(filename: &Path) -> Result<(), Error> {
    let mut guard = LUA_MASTER.lock().unwrap();
    let script = std::fs::read_to_string(filename).context(format!("opening {:?}", filename))?;
    let lua = Lua::new();
    if let Err::<(), _>(e) = lua.context(|ctx| {
        // set globals
        set_globals(ctx);
        // load the script.
        let chunk = ctx.load(&script);
        let chunk = chunk.set_name(filename.as_os_str().as_bytes())?;
        chunk.exec()
    }) {
        merror!("parsing lua script:\n{}", e);
        Err(WnError::LuaError)?;
    }
    // if there is an "init" function, run it.
    if let Err::<(), _>(e) = lua.context(|ctx| {
        if let Ok::<Function, _>(func) = ctx.globals().get("init") {
            return func.call::<_, rlua::MultiValue>(()).map(|_| ())
        }
        Ok(())
    }) {
        merror!("calling lua init():\n{}", e);
        Err(WnError::LuaError)?;
    }

    let lua_master = &mut *guard;
    *lua_master = Some(LuaMaster {
        name:   filename.to_string_lossy().to_string(),
        script: script,
    });
    Ok(())
}

/// Recursively transform a serde_json::Value to a rlua::Value.
/// This is surprisingly easy!
fn json_value_to_lua<'lua>(ctx: rlua::Context<'lua>, jv: &serde_json::Value) -> rlua::Value<'lua> {
    match jv {
        &serde_json::Value::Null => rlua::Nil,
        &serde_json::Value::Bool(ref b) => (*b).to_lua(ctx).unwrap(),
        &serde_json::Value::Number(ref n) => {
            if let Some(n) = n.as_i64() {
                n.to_lua(ctx).unwrap()
            } else if let Some(n) = n.as_f64() {
                n.to_lua(ctx).unwrap()
            } else {
                rlua::Nil
            }
        },
        &serde_json::Value::String(ref s) => s.as_str().to_lua(ctx).unwrap(),
        &serde_json::Value::Array(ref a) => {
            a.iter()
                .map(|e| json_value_to_lua(ctx, e))
                .collect::<Vec<_>>()
                .to_lua(ctx)
                .unwrap_or(rlua::Nil)
        },
        &serde_json::Value::Object(ref o) => {
            ctx.create_table().and_then(|table| {
                for (k, v) in o.iter() {
                    let _ = table.set(k.as_str(), json_value_to_lua(ctx, v));
                }
                table.to_lua(ctx)
            }).unwrap_or(rlua::Nil)
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
                let v = t
                    .sequence_values::<rlua::Value>()
                    .filter_map(|res| res.ok())
                    .map(|e| lua_value_to_json(e))
                    .collect::<Vec<_>>();
                JValue::Array(v)
            } else {
                // It is an object.
                let hm = serde_json::map::Map::from_iter(
                    t.pairs::<String, rlua::Value>()
                        .filter_map(|res| res.ok())
                        .map(|(k, v)| (k, lua_value_to_json(v))),
                );
                JValue::Object(hm)
            }
        },
        _ => JValue::Null,
    }
}

/// This struct contains a refcounted Datalog. It's so that we can
/// store it in the Request struct _and_ transform it into a AnyUserData.
#[derive(Clone)]
pub(crate) struct DatalogRef(Arc<Mutex<Option<Datalog>>>);

/// Some constructors.
impl DatalogRef {
    #[allow(dead_code)]
    pub fn new(d: Datalog) -> DatalogRef {
        DatalogRef(Arc::new(Mutex::new(Some(d))))
    }

    pub fn set(&self, d: Datalog) {
        let mut guard = self.0.lock().unwrap();
        *guard = Some(d);
    }
}

/// Default since Request must implement Default.
impl Default for DatalogRef {
    fn default() -> DatalogRef {
        DatalogRef(Arc::new(Mutex::new(None)))
    }
}

impl UserData for DatalogRef {
    ///
    /// Add just the NewIndex method here, for log.<key> = value.
    ///
    fn add_methods<'lua, M: UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_meta_method(MetaMethod::NewIndex, |_ctx, this: &DatalogRef, (key, value) : (String, rlua::Value)| {

            // Ignore if the inner Datalog is not set.
            let mut this = this.0.lock().unwrap();
            let datalog = match this.as_mut() {
                Some(d) => d,
                None => return Ok(rlua::Nil),
            };

            // set table entry.
            match key.as_str() {
                "account" => match value {
                    rlua::Value::String(v) => {
                        datalog.account = Some(v.to_str()?.to_owned());
                    },
                    _ => return Err(rlua::Error::external("log.account = val: must be a string")),
                },
                "status" => match value {
                    rlua::Value::Integer(v) => {
                        let n = v as usize;
                        datalog.status = Err(n.into());
                    },
                    _ => return Err(rlua::Error::external("log.status = val: must be a datalog.enum")),
                },
                x => return Err(rlua::Error::external(format!("log.{}: unknown key", x))),
            }
            Ok(rlua::Nil)
        });
    }
}

/// This contains data from the request. It is implemented as a Lua userdata
/// struct, and passed to the lua auth/lookup hooks.
#[derive(Default)]
pub(crate) struct Request {
    pub domain:   String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub mapname:  Option<String>,
    pub keyname:  Option<String>,
    pub keyvalue: Option<String>,
    pub extra:    HashMap<String, serde_json::Value>,
    pub src_ip:   Option<IpAddr>,
    pub log:      DatalogRef,
}

impl UserData for Request {
    fn add_methods<'lua, M: UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_meta_method(MetaMethod::Index, |ctx, this: &Request, arg: String| {
            // table entry lookup.
            let r = match arg.as_str() {
                "domain" => this.domain.as_str().to_lua(ctx).ok(),
                "username" => this.username.as_ref().and_then(|x| x.as_str().to_lua(ctx).ok()),
                "password" => this.password.as_ref().and_then(|x| x.as_str().to_lua(ctx).ok()),
                "mapname" => this.keyname.as_ref().and_then(|x| x.as_str().to_lua(ctx).ok()),
                "keyname" => this.keyname.as_ref().and_then(|x| x.as_str().to_lua(ctx).ok()),
                "keyvalue" => this.keyvalue.as_ref().and_then(|x| x.as_str().to_lua(ctx).ok()),
                "log" => {
                    let log = this.log.clone();
                    let ud = ctx.create_userdata(log).and_then(|x| x.to_lua(ctx));
                    ud.ok()
                },
                x => {
                    if let Some(jv) = this.extra.get(x) {
                        Some(json_value_to_lua(ctx, jv))
                    } else {
                        None
                    }
                },
            };
            Ok(r)
        });

        // check the password in the Request struct against a
        // password hash (that we probably got from a map lookup).
        methods.add_method("checkpass", |_, this: &Request, arg: String| {
            if let Some(ref password) = this.password {
                Ok(util::check_unix_password(password, &arg))
            } else {
                Ok(false)
            }
        });
    }
}

/// lua_map calls a lua function. The return value is usually a map, or nil.
pub(crate) fn lua_map(
    webnis: &Webnis,
    funcname: &str,
    domain: &str,
    keyname: &str,
    keyvalue: &str,
) -> Result<serde_json::Value, WnError>
{
    LUA.with(|lua_tls| {
        let mut lua_state = lua_tls.borrow();
        if !lua_state.did_init {
            drop(lua_state);
            let mut lua_state_mut = lua_tls.borrow_mut();
	        let webnis = webnis.clone();
            lua_state_mut.lua.context(|ctx| set_webnis_global(ctx, webnis));
            lua_state_mut.did_init = true;
            drop(lua_state_mut);
            lua_state = lua_tls.borrow();
        }

        lua_state.lua.context(|ctx| {
            // create Request.
            let req = Request{
                domain:     domain.to_string(),
                keyname:    Some(keyname.to_string()),
                keyvalue:   Some(keyvalue.to_string()),
                ..Request::default()
            };

            // find the lua function we need to call by name.
            let func: Function = match ctx.globals().get(funcname) {
                Ok(f) => f,
                Err(_e) => return Err(WnError::LuaFunctionNotFound),
            };

            // Call the function
            let val = match func.call::<_, rlua::Value>(req) {
                Ok(v) => v,
                Err(e) => {
                    merror!("lua_map: executing {}:\n{}", funcname, e);
                    return Err(WnError::LuaError);
                },
            };

            let jv = lua_value_to_json(val);
            Ok(jv)
        })
    })
}

/// lua_auth calls a lua function.
/// returns a json value on success, json null on auth fail, error on any errors.
pub(crate) fn lua_auth(
    webnis: &Webnis,
    funcname: &str,
    req: Request,
) -> Result<(serde_json::Value, u16), WnError>
{
    let do_log = webnis.inner.config.server.datalog.is_some();

    LUA.with(|lua_tls| {
        let mut lua_state = lua_tls.borrow();
        if !lua_state.did_init {
            drop(lua_state);
            let mut lua_state_mut = lua_tls.borrow_mut();
	        let webnis = webnis.clone();
            lua_state_mut.lua.context(|ctx| set_webnis_global(ctx, webnis));
            lua_state_mut.did_init = true;
            drop(lua_state_mut);
            lua_state = lua_tls.borrow();
        }

        if do_log {
            // set up the datalog member.
            let clientip = match req.extra.get("clientip") {
                Some(serde_json::Value::String(ref s)) => s.parse::<IpAddr>().ok(),
                _ => None,
            };
            let callingsystem = match req.extra.get("callingsystem") {
                Some(serde_json::Value::String(ref s)) => Some(s.clone()),
                _ => None,
            };
            req.log.set(Datalog{
                time:   SystemTime::now(),
                username:       req.username.clone().unwrap_or("".into()),
                src_ip:         req.src_ip.unwrap_or([0, 0, 0, 0].into()),
                clientip:       clientip,
                callingsystem:  callingsystem,
                ..Datalog::default()
            });
        }
        let datalog_ref = req.log.clone();

        let res = lua_state.lua.context(|ctx| {
            let func: Function = match ctx.globals().get(funcname) {
                Ok(f) => f,
                Err(_e) => return Err(WnError::LuaFunctionNotFound),
            };

            // function can return 0, 1 or 2 values.
            let multival = match func.call::<_, rlua::MultiValue>(req) {
                Ok(v) => v,
                Err(e) => {
                    merror!("lua_auth: executing {}:\n{}", funcname, e);
                    return Err(WnError::LuaError);
                },
            };
            let mut vals = multival.into_iter();

            // first value, if present, is the returned table.
            let jv = vals
                .next()
                .map(|v| lua_value_to_json(v))
                .unwrap_or(serde_json::Value::Null);

            // second value, if present, is statuscode.
            let code = {
                match vals.next() {
                    Some(rlua::Value::Integer(n)) => {
                        if n < 100 || n > 599 {
                            merror!(
                                "lua_auth: executing {}: status code out of range: {}\n",
                                funcname,
                                n
                            );
                            return Err(WnError::LuaError);
                        }
                        n as u16
                    },
                    Some(_) => {
                        merror!("lua_auth: executing {}: status code not an integer\n", funcname);
                        return Err(WnError::LuaError);
                    },
                    None => 0,
                }
            };

            Ok((jv, code))
        });

        // See if we need to update the log status.
        if do_log {
            let mut dl = datalog_ref.0.lock().unwrap().take().unwrap();
            match res {
                Err(ref e) => {
                    // internal error, override log status.
                    dl.status = Err(datalog::Error::GENERIC);
                    dl.message = Some(format!("{:?}", e));
                },
                Ok(ref v) => {
                    if v.0 == serde_json::Value::Null || v.1 >= 400 {
                        // It's a reject, if status was not set do it now.
                        if dl.status.is_ok() {
                            dl.status = Err(datalog::Error::GENERIC);
                        }
                    }
                }
            }
            // And log.
            datalog::log_sync(dl);
        }

        res
    })
}

fn set_webnis_global(ctx: rlua::Context, webnis: Webnis) {
    let table = ctx.create_table().expect("failed to create table");
    let globals = ctx.globals();

    let map_lookup = {
        let webnis = webnis.clone();
        ctx.create_function(
            move |ctx, (req, mapname, keyname, keyvalue): (rlua::AnyUserData, String, String, String)| {
                let req = match req.borrow::<Request>() {
                    Ok(r) => r,
                    Err(e) => return Err(e),
                };
                let v = match webnis.lua_map_lookup(&req.domain, &mapname, &keyname, &keyvalue) {
                    Ok(jv) => json_value_to_lua(ctx, &jv),
                    Err(e) => {
                        warn!("map_lookup {} {}={}: {}", mapname, keyname, keyvalue, e);
                        rlua::Nil
                    },
                };
                Ok(v)
            },
        )
        .expect("failed to create func map_lookup()")
    };
    table
        .set("map_lookup", map_lookup)
        .expect("failed to insert into table");

    let map_auth = {
        ctx.create_function(
            move |ctx, (req, mapname, keyname, username): (rlua::AnyUserData, String, String, String)| {
                let req = match req.borrow::<Request>() {
                    Ok(r) => r,
                    Err(e) => return Err(e),
                };
                let password = req.password.as_ref().ok_or(rlua::Error::RuntimeError("password not set".into()))?;
                let v = match webnis.lua_map_auth(&req.domain, &mapname, &keyname, &username, &password) {
                    Ok(jv) => json_value_to_lua(ctx, &JValue::Bool(jv)),
                    Err(e) => {
                        warn!("map_auth {} {}={}: {}", mapname, keyname, username, e);
                        rlua::Nil
                    },
                };
                Ok(v)
            },
        )
        .expect("failed to create func map_lookup()")
    };
    table
        .set("map_auth", map_auth)
        .expect("failed to insert into table");

    globals.set("webnis", table).expect("failed to set global webnis");
}

fn set_globals(ctx: rlua::Context) {
    let globals = ctx.globals();

    // The error global table.
    let error_table = ctx.create_table().expect("failed to create error table");
    for (_, num, name) in datalog::error_iter() {
        error_table.set(name, num).expect("failed to insert into error table");
    }
    globals.set("error", error_table).expect("failed to set global error table");

    // add a debugging function.
    let dprint = ctx
        .create_function(|_, data: String| {
            debug!("{}", data);
            Ok(())
        })
        .unwrap();
    globals.set("dprint", dprint).unwrap();

    // add a syslog logging function.
    let logprint = ctx
        .create_function(|_, data: String| {
            do_syslog(&data);
            Ok(())
        })
        .unwrap();
    globals.set("logprint", logprint).unwrap();
}

