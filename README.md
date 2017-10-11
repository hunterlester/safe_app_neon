# safe_app_neon

experiment to replace https://github.com/maidsafe/safe_app_nodejs

The following setup is if you want to experiment and compile source code, otherwise you'll simply be including this library as an app dependency, as is done here: https://github.com/hunterlester/neon-safe-app-example

##### Setup:
- Initial setup with Neon guide: https://guides.neon-bindings.com/getting-started/
- Setup may not be very smooth on Windows, contact me for help, if needed
- `npm install`
- Although you'll use `neon build` to compile and build addons, this is not efficient for working through compiler errors, because it doesn't cache compiled dependencies. Instead, just use `cargo build`
- See further Neon guide: https://guides.neon-bindings.com/hello-world/
