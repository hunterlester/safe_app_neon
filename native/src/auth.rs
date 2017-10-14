extern crate neon;
extern crate safe_core;
extern crate maidsafe_utilities;
extern crate ffi_utils;
extern crate serde_json;

use self::neon::vm::{ Call, JsResult };
use self::neon::js::{ JsString, JsBoolean };
use self::neon::js::error::{ JsError, Kind };

use self::serde_json::{ Value };

use std::convert::From;
use std::collections::{ HashMap, BTreeSet };

use self::safe_core::ipc::{ self, AuthReq, IpcReq, IpcResp, IpcMsg, Permission, AppExchangeInfo };
use self::ffi_utils::{ base64_encode };
use self::maidsafe_utilities::serialisation::{ serialise };

pub fn decode_ipc_msg(call: Call) -> JsResult<JsString> {
    let scope = call.scope;
    let uri_string = call.arguments.require(scope, 0)?.check::<JsString>()?.value();
    let msg = ipc::decode_msg(&uri_string).or_else(|e| JsError::throw(Kind::Error, format!("Error occured while decoding IPC message: {:?}", e).as_str()))?;;
    println!("decoded msg: {:?}", &msg);
    match msg {
        IpcMsg::Resp {
            resp: IpcResp::Auth(res),
            req_id,
        } => println!("ipcResp: {:?}, req_id: {:?}", res, req_id),
        _ => (),
    }
    Ok(JsString::new(scope, "URI opened").unwrap())
}

// TODO: move functions like this into a separate crate concerning only safe_client_libs Rust API
fn encode_auth_req(req: AuthReq) -> String {
  let req_id = ipc::gen_req_id();
  let ipc_req = IpcReq::Auth(req);
  let ipc_msg = &IpcMsg::Req { req_id: req_id, req: ipc_req};
  let serialised_ipc_msg = serialise(ipc_msg).unwrap();
  let payload = base64_encode(&serialised_ipc_msg);
  format!("safe-auth:{}", payload)
}

pub fn gen_auth_uri(call: Call) -> JsResult<JsString> {
  let scope = call.scope;

  let app_info_string = call.arguments.require(scope, 0)?.check::<JsString>()?.value();
  let app_info: Value = serde_json::from_str(&app_info_string).or_else(|e| JsError::throw(Kind::Error, format!("Error occured while creating JSON object: {:?}", e).as_str()))?;
  println!("appInfo for gen_auth_uri: {:?}", &app_info);

  let mut container_permissions = HashMap::new();
  let permissions_string = call.arguments.require(scope, 1)?.check::<JsString>()?.value();
  let permissions_object: Value = serde_json::from_str(&permissions_string).or_else(|e| JsError::throw(Kind::Error, format!("Error occured while creating JSON object: {:?}", e).as_str()))?;

  let keys: Vec<&str> = permissions_object.as_object().unwrap().keys().map(|key| key.as_str()).collect();
  for key in keys {
      let mut permissions = BTreeSet::new();

      let perms_vec: &Vec<Value> = permissions_object.get(key).unwrap().as_array().unwrap();
      for perm in perms_vec {
        match perm.as_str().unwrap() {
            "Read" => permissions.insert(Permission::Read),
            "Insert" => permissions.insert(Permission::Insert),
            "Update" => permissions.insert(Permission::Update),
            "Delete" => permissions.insert(Permission::Delete),
            "ManagePermissions" => permissions.insert(Permission::ManagePermissions),
            _ => false,
        };
      }
      container_permissions.insert(String::from(key), permissions);
  }

  let own_container = call.arguments.require(scope, 2)?.check::<JsBoolean>()?.value();
  println!("own_container: {:?}", own_container);

  let auth_request = AuthReq {
    app: AppExchangeInfo {
      id: String::from(app_info["id"].as_str().unwrap()),
      scope: None,
      name: String::from(app_info["name"].as_str().unwrap()),
      vendor: String::from(app_info["vendor"].as_str().unwrap()),
    },
    app_container: own_container,
    containers: container_permissions,
  };

  println!("auth_request for gen_auth_uri: {:?}", &auth_request);

  let auth_uri = encode_auth_req(auth_request);
  println!("auth_uri for gen_auth_uri: {:?}", &auth_uri);
  Ok(JsString::new(scope, auth_uri.as_str()).unwrap())
}
