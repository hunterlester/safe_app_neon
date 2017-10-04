#[macro_use]
extern crate neon;
extern crate safe_core;
extern crate maidsafe_utilities;
extern crate ffi_utils;

use neon::vm::{Call, JsResult};
use neon::js::JsString;

use safe_core::ipc::{ self, AuthReq, IpcReq, IpcMsg, Permission, AppExchangeInfo };
use ffi_utils::{ base64_encode };
use maidsafe_utilities::serialisation::{ serialise };
use std::collections::{ HashMap, BTreeSet };

fn hello(call: Call) -> JsResult<JsString> {
    let scope = call.scope;
    Ok(JsString::new(scope, "hello node").unwrap())
}

fn encode_auth_req(req: AuthReq) -> String {
  let req_id = ipc::gen_req_id();
  let ipc_req = IpcReq::Auth(req);
  let ipc_msg = &IpcMsg::Req { req_id: req_id, req: ipc_req};
  println!("{:?}", &ipc_msg);
  let serialised_ipc_msg = serialise(ipc_msg).unwrap();
  println!("{:?}", &serialised_ipc_msg);
  let payload = base64_encode(&serialised_ipc_msg);
  println!("{:?}", payload);
  format!("safe-auth:{}", payload)
}

fn gen_auth_uri(call: Call) -> JsResult<JsString> {
  let mut permissions = BTreeSet::new();
  permissions.insert(Permission::Read);
  permissions.insert(Permission::Insert);
  permissions.insert(Permission::Update);
  permissions.insert(Permission::Delete);
  permissions.insert(Permission::ManagePermissions);

  let mut container_permissions = HashMap::new();
  container_permissions.insert(String::from("_public"), permissions);

  let auth_request = AuthReq {
    app: AppExchangeInfo {
      id: String::from("test.id.neon"),
      scope: Some(String::from("")),
      name: String::from("TEST APP"),
      vendor: String::from("MAIDSAFE"),
    },
    app_container: false,
    containers: container_permissions,
  };

  let auth_uri = encode_auth_req(auth_request);
  let scope = call.scope;
  Ok(JsString::new(scope, auth_uri.as_str()).unwrap())
}

register_module!(m, {
    m.export("hello", hello)?;
    m.export("gen_auth_uri", gen_auth_uri)?;
    Ok(())
});
