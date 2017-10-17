#[macro_use]
extern crate neon;

extern crate serde_json;
extern crate safe_core;
extern crate maidsafe_utilities;
extern crate ffi_utils;
extern crate safe_app;
extern crate system_uri;

mod auth;
mod uri;

use auth::*;
use uri::*;

register_module!(m, {
    m.export("install", install)?;
    m.export("gen_auth_uri", gen_auth_uri)?;
    m.export("open", open)?;
    m.export("connect", connect)?;
    Ok(())
});
