
use libc::{uid_t, gid_t};
use errors::*;

pub(crate) fn get_user_gids(name: &str) -> ConnxResult<String> {
    if name == "truus" {
        return Ok("truus:42,1337,1,2,3,4,5,6,7,8,9,10,11,12".to_owned());
    }
    Err(ConnxRetrievalError::NotFound)
}

pub(crate) fn get_group_by_name(name: &str) -> ConnxResult<String> {
    if name == "truus" {
        return Ok("truus:x:42:".to_owned());
    }
    Err(ConnxRetrievalError::NotFound)
}

pub(crate) fn get_group_by_gid(gid: gid_t) -> ConnxResult<String> {
    if gid == 42 {
        return Ok("truus:x:42:".to_owned());
    }
    if gid == 1337 {
        return Ok("truus2:x:1337:".to_owned());
    }
    Err(ConnxRetrievalError::NotFound)
}

pub(crate) fn get_user_by_name(name: &str) -> ConnxResult<String> {
    if name == "truus" {
        return Ok("truus:x:1042:42:Truus:/home/truus:".to_owned());
    }
    Err(ConnxRetrievalError::NotFound)
}

pub(crate) fn get_user_by_uid(uid: uid_t) -> ConnxResult<String> {
    if uid == 1042 {
        return Ok("truus:x:1042:42:Truus:/home/truus:".to_owned());
    }
    Err(ConnxRetrievalError::NotFound)
}

