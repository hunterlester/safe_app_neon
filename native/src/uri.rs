extern crate neon;
extern crate system_uri;
extern crate serde_json;

use self::neon::js::{ JsString };
use self::neon::vm::{ Call, JsResult };
use self::neon::js::error::{ JsError, Kind };

use self::serde_json::{ Value };

use self::system_uri::{ App, install as uri_install, open as uri_open };

pub fn open(call: Call) -> JsResult<JsString> {
    let scope = call.scope;
    let uri_string = call.arguments.require(scope, 0)?.check::<JsString>()?.value();
    println!("uri_string to open: {:?}", &uri_string);
    uri_open(uri_string).unwrap();
    Ok(JsString::new(scope, "URI opened").unwrap())
}

pub fn install(call: Call) -> JsResult<JsString> {
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
