use neon::vm::{ Call, JsResult };
// Lock
use neon::js::{ JsString, JsBoolean, JsInteger, JsArray };
use neon::js::error::{ JsError, Kind };
use neon::js::binary::{ JsBuffer };

use serde_json::{ self, Value };

use std::convert::From;
use std::collections::{ HashMap, BTreeSet };

use safe_core::ipc::{ self, AuthReq, IpcReq, IpcResp, IpcMsg, Permission, AppExchangeInfo, IpcError };
use ffi_utils::{ base64_encode };
use maidsafe_utilities::serialisation::{ serialise };
use safe_app::{ App, AppError };

// reference : https://github.com/dherman/neon-class-example/blob/master/native/src/lib.rs
declare_types! {
    pub class JsApp for App {
        // init will connect application to network and return App struct
        init(call) {
            let scope = call.scope;
            let app_info_string: String = call.arguments.require(scope, 0)?.check::<JsString>()?.value();
            let app_info: Value = serde_json::from_str(&app_info_string).or_else(|e| JsError::throw(Kind::Error, format!("Error occured while creating JSON object: {:?}", e).as_str()))?;
            let uri_string = call.arguments.require(scope, 1)?.check::<JsString>()?.value();
            let app = decode_ipc_msg(String::from(app_info["id"].as_str().unwrap()), uri_string).unwrap();
            Ok(app)
        }
        // Declare methods here that utilise App struct
        // method generic(call) {
        //     let scope = call.scope;
        //     let output = call.arguments.this(scope).grab(|app| {
        //         network_fn(app, arg1, arg2)
        //     });
        //     Ok(output)
        // }
    }
}

fn decode_ipc_msg(app_id: String, uri_string: String) -> Result<???, AppError> {
    let msg = ipc::decode_msg(&uri_string).unwrap();
    println!("decoded msg: {:?}", &msg);
    match msg {
        IpcMsg::Resp {
            resp: IpcResp::Auth(res),
            req_id,
        } => {
            match res {
                Ok(auth_granted) => App::registered(app_id, auth_granted, move |event| {println!("Network state: {:?}", event)}),
                Err(err) => Err(AppError::from(err)),
            }
        },
        IpcMsg::Resp {
            resp: IpcResp::Containers(res),
            req_id,
        } => {
            match res {
                Ok(()) => req_id,
                Err(err) => AppError::from(err)
            }
        },
        IpcMsg::Resp {
            resp: IpcResp::Unregistered(res),
            req_id,
        } => {
            match res {
                Ok(bootstrap_cfg) => serialise(&bootstrap_cfg)?,
                Err(err) => AppError::from(err)
            }
        },
        IpcMsg::Resp {
            resp: IpcResp::ShareMData(res),
            req_id,
        } => {
            match res {
                Ok(()) => req_id,
                Err(err) => AppError::from(err),
            }
        },
        IpcMsg::Revoked { .. } => app_id,
        _ => {
            return Err(IpcError::InvalidMsg.into());
        }
    }
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
