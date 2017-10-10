#[macro_use]
extern crate neon;
extern crate safe_core;
extern crate maidsafe_utilities;
extern crate ffi_utils;
extern crate system_uri;
extern crate serde_json;

use neon::vm::{ Call, JsResult };
use neon::js::{ JsString };
use neon::js::error::{ JsError, Kind };
use std::convert::From;

use safe_core::ipc::{ self, AuthReq, IpcReq, IpcMsg, Permission, AppExchangeInfo };
use ffi_utils::{ base64_encode };
use maidsafe_utilities::serialisation::{ serialise };
use std::collections::{ HashMap, BTreeSet };
use system_uri::{ App, install as uri_install };
use serde_json::{ Value };

fn install(call: Call) -> JsResult<JsString> {
  let scope = call.scope;
  let app_info_string = call.arguments.require(scope, 0)?.check::<JsString>()?.value();
  let app_info: Value = serde_json::from_str(&app_info_string).or_else(|e| JsError::throw(Kind::Error, format!("Error occured while creating JSON object: {:?}", e).as_str()))?;
  println!("install app info: {:?}", &app_info);
  let app = App::new(
      String::from(app_info["id"].as_str().unwrap()),
      String::from(app_info["vendor"].as_str().unwrap()),
      String::from(app_info["name"].as_str().unwrap()),
      String::from(app_info["exec"].as_str().unwrap()),
      Some(String::from(app_info["icon"].as_str().unwrap())),
  );
  println!("appInfo for install: {:?}", &app);
  let schemes = String::from("safe-dgvzdc5pzc5uzw9u");
  uri_install(
    &app,
    &schemes
        .split(',')
        .map(|s| s.to_string())
        .collect::<Vec<_>>(),
  ).unwrap();
  Ok(JsString::new(scope, "URI registry complete").unwrap())
}

fn encode_auth_req(req: AuthReq) -> String {
  let req_id = ipc::gen_req_id();
  let ipc_req = IpcReq::Auth(req);
  let ipc_msg = &IpcMsg::Req { req_id: req_id, req: ipc_req};
  let serialised_ipc_msg = serialise(ipc_msg).unwrap();
  let payload = base64_encode(&serialised_ipc_msg);
  format!("safe-auth:{}", payload)
}

fn gen_auth_uri(call: Call) -> JsResult<JsString> {
  let scope = call.scope;
  let mut permissions = BTreeSet::new();
  permissions.insert(Permission::Read);
  permissions.insert(Permission::Insert);
  permissions.insert(Permission::Update);
  permissions.insert(Permission::Delete);
  permissions.insert(Permission::ManagePermissions);

  let mut container_permissions = HashMap::new();
  container_permissions.insert(String::from("_public"), permissions);

  let app_info_string = call.arguments.require(scope, 0)?.check::<JsString>()?.value();
  let app_info: Value = serde_json::from_str(&app_info_string).or_else(|e| JsError::throw(Kind::Error, format!("Error occured while creating JSON object: {:?}", e).as_str()))?;
  println!("appInfo for gen_auth_uri: {:?}", &app_info);

  let auth_request = AuthReq {
    app: AppExchangeInfo {
      id: String::from(app_info["id"].as_str().unwrap()),
      scope: None,
      name: String::from(app_info["name"].as_str().unwrap()),
      vendor: String::from(app_info["vendor"].as_str().unwrap()),
    },
    app_container: true,
    containers: container_permissions,
  };

  println!("auth_request for gen_auth_uri: {:?}", &auth_request);

  let auth_uri = encode_auth_req(auth_request);
  println!("auth_uri for gen_auth_uri: {:?}", &auth_uri);
  Ok(JsString::new(scope, auth_uri.as_str()).unwrap())
}

register_module!(m, {
    m.export("install", install)?;
    m.export("gen_auth_uri", gen_auth_uri)?;
    Ok(())
});
