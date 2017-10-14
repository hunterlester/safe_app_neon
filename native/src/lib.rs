#[macro_use]
extern crate neon;

mod auth;
mod uri;

use auth::*;
use uri::*;

register_module!(m, {
    m.export("install", install)?;
    m.export("gen_auth_uri", gen_auth_uri)?;
    m.export("open", open)?;
    m.export("decode_ipc_msg", decode_ipc_msg)?;
    Ok(())
});
